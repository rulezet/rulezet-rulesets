rule SUSP_Macho_AES_CBC_Mode_XOR {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check Macho files for what might be an AES XOR routine used in its CBC mode "

  strings:
    $aes_cbc_xor_movs = { 0f b6 48 01 41 30 4c 1d 01 0f b6 48 02 41 30 4c 1d 02 0f b6 48 03 41 30 4c 1d 03 0f b6 48 04 41 30 4c 1d 04 0f b6 48 05 41 30 4c 1d 05 0f b6 48 06 41 30 4c 1d 06 0f b6 48 07 41 30 4c 1d 07 0f b6 48 08 41 30 4c 1d 08 0f b6 48 09 41 30 4c 1d 09 0f b6 48 0a 41 30 4c 1d 0a 0f b6 48 0b 41 30 4c 1d 0b 0f b6 48 0c 41 30 4c 1d 0c 0f b6 48 0d 41 30 4c 1d 0d 0f b6 48 0e 41 30 4c 1d 0e 0f b6 40 0f 41 30 44 1d 0f }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}