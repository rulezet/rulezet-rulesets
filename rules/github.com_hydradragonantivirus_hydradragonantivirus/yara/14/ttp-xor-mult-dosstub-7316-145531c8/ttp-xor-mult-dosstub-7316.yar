rule TTP_XOR_MULT_DOSStub_7316 {
  strings:
    $key_7316 = { 27 7e [2] 53 66 [2] 14 64 [2] 53 75 [2] 1d 79 [2] 11 73 [2] 06 78 [2] 1d 36 [2] 20 }

  condition:
    any of them
}