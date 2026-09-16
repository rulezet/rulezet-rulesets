rule b64_doc
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_doc = "0M8R4"     condition:
        $b64_doc at 0

}