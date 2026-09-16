rule TTP_XOR_MULT_DOSStub_6401 {
  strings:
    $key_6401 = { 30 69 [2] 44 71 [2] 03 73 [2] 44 62 [2] 0a 6e [2] 06 64 [2] 11 6f [2] 0a 21 [2] 37 }

  condition:
    any of them
}