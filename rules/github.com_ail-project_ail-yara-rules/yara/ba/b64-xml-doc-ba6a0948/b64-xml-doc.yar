rule b64_xml_doc
{
    meta:
        author = "@KevTheHermit"
        info = "Part of PasteHunter"
        reference = "https://github.com/kevthehermit/PasteHunter"

    strings:
        $b64_xml = "PD94bWwg"
        $docx1 = "b3BlbmRvY3VtZW50"         $docx2 = "InBhcmFncmFwaCI"         $docx3 = "b2ZmaWNlL3dvcmQv"         $docx4 = "RG9jdW1lbnRQcm9wZXJ0aWVz"     condition:
        $b64_xml at 0 and 3 of ($docx*)

}