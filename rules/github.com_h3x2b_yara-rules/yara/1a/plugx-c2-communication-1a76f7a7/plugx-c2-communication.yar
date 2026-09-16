rule plugx_c2_communication : APT
{
    meta:
        description = "Match the DZKS....DZJS C2 string"
        author = "@h3x2b <tracker _AT h3x.eu>"

    strings:
        $s1 = /DZKS[A-Z]*DZJS/

    condition:
        any of them

}