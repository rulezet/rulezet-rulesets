rule pdf_document
{
  strings:
    $a = "%PDF-"
  condition:
    $a at 0
}