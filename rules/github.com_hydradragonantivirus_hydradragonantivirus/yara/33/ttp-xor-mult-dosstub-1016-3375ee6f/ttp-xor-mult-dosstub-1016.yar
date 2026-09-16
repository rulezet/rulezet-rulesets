rule TTP_XOR_MULT_DOSStub_1016 {
  strings:
    $key_1016 = { 44 7e [2] 30 66 [2] 77 64 [2] 30 75 [2] 7e 79 [2] 72 73 [2] 65 78 [2] 7e 36 [2] 43 }

  condition:
    any of them
}