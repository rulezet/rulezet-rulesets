rule embed_wrong_version_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    description = "EmbeddedFiles were introduced in v1.3"
    ref         = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
    version     = "0.1"
    weight      = 1

  strings:
    $magic = "%PDF"
    $embed = /\/EmbeddedFiles/
    $ver   = /%PDF-1\.[3-9]/

  condition:
    $magic at 0 and $embed and not $ver
}