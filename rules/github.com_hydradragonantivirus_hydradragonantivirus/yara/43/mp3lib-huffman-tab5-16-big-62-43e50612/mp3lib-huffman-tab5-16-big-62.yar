rule mp3lib_huffman_tab5__16_big_62_ {
  strings:
    $a0 = { FF E3 FF E7 FF E9 FF F1 FF F9 FF FB FF FD FF FF 00 33 00 23 00 32 00 31 FF FD FF FF 00 13 00 03 FF FF 00 30 00 22 FF FD FF FF 00 12 00 21 FF FF 00 02 00 20 00 11 FF FF 00 01 00 10 00 00 }

  condition:
    $a0
}