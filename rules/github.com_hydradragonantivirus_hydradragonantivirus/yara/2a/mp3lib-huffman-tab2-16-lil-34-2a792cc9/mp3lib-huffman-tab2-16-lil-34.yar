rule mp3lib_huffman_tab2__16_lil_34_ {
  strings:
    $a0 = { F1 FF F5 FF F7 FF FB FF FD FF FF FF 22 00 02 00 12 00 FF FF 21 00 20 00 11 00 FF FF 01 00 10 00 00 00 }

  condition:
    $a0
}