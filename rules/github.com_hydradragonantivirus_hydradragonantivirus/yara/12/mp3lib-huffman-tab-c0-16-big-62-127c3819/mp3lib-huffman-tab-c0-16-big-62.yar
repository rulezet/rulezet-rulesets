rule mp3lib_huffman_tab_c0__16_big_62_ {
  strings:
    $a0 = { FF E3 FF EB FF F3 FF F9 FF FD FF FF 00 0B 00 0F FF FF 00 0D 00 0E FF FD FF FF 00 07 00 05 00 09 FF FD FF FF 00 06 00 03 FF FF 00 0A 00 0C FF FD FF FF 00 02 00 01 FF FF 00 04 00 08 00 00 }

  condition:
    $a0
}