rule misc_hexascii_pe_in_html : encoding html suspicious
{
    meta:
        author = "Jason Batchelor"
        created = "2016-03-02"
        modified = "2016-03-02"
        university = "Carnegie Mellon University"
        description = "Detect on presence of hexascii encoded executable inside scripted code section of html file"

    strings:
        $html_start = "<html>" ascii nocase         $html_end = "</html>" ascii nocase
        $mz = "4d5a"  ascii nocase         $pe = "50450000" ascii nocase 
    condition:
        all of ($html*) and $pe in (@mz[1] .. filesize)
}