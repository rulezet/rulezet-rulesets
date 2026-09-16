rule mp3lib_huffman_tab_c0__16_lil_62_ {
  strings:
    $a0 = { E3 FF EB FF F3 FF F9 FF FD FF FF FF 0B 00 0F 00 FF FF 0D 00 0E 00 FD FF FF FF 07 00 05 00 09 00 FD FF FF FF 06 00 03 00 FF FF 0A 00 0C 00 FD FF FF FF 02 00 01 00 FF FF 04 00 08 00 00 00 }

  condition:
    $a0
}