rule TTP_XOR_MULT_DOSStub_4516 {
  strings:
    $key_4516 = { 11 7e [2] 65 66 [2] 22 64 [2] 65 75 [2] 2b 79 [2] 27 73 [2] 30 78 [2] 2b 36 [2] 16 }

  condition:
    any of them
}