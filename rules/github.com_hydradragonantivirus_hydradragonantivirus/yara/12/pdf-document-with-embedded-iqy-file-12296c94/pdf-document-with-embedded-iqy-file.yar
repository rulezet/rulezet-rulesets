rule PDF_Document_with_Embedded_IQY_File {
  meta:
    Author      = "InQuest Labs"
    Description = "This signature detects IQY files embedded within PDF documents which use a JavaScript OpenAction object to run the IQY."
    Reference   = "https://blog.inquest.net"

  strings:
    $pdf_magic  = "%PDF"
    $efile      = /<<\/JavaScript [^\x3e]+\/EmbeddedFile/
    $fspec      = /<<\/Type\/Filespec\/F\(\w+\.iqy\)\/UF\(\w+\.iqy\)/
    $openaction = /OpenAction<<\/S\/JavaScript\/JS\(/

  

  

  condition:
    $pdf_magic in (0..60) and all of them
}