rule b64_docx
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_zip = "UEs"
        $docx1 = "d29yZC9fcmVsc"         $docx2 = "Zm9udFRhYmxl"         $docx3 = "ZG9jUHJvcHM"         $docx4 = "Q29udGVudF9UeXBlcw"         $docx5 = "c2V0dGluZ3M"     condition:
        $b64_zip at 0 and 3 of ($docx*)

}