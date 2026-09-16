rule SUSP_Macho_XOR_Encoded_Macho {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-04"
    version     = "1.0"
    description = "check Macho samples for additional Macho magic bytes"

  strings:
    $CFFAEDFE = "\xCF\xFA\xED\xFE" xor(0x01-0xff) ascii wide
    $CEFAEDFE = "\xCE\xFA\xED\xFE" xor(0x01-0xff) ascii wide
    $text     = "__TEXT" xor(0x01-0xff) ascii wide

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and 2 of them
}