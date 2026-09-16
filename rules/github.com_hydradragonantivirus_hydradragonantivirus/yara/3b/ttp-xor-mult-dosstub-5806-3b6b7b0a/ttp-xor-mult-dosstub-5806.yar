rule TTP_XOR_MULT_DOSStub_5806 {
  strings:
    $key_5806 = { 0c 6e [2] 78 76 [2] 3f 74 [2] 78 65 [2] 36 69 [2] 3a 63 [2] 2d 68 [2] 36 26 [2] 0b }

  condition:
    any of them
}