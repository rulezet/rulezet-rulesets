rule TTP_XOR_MULT_DOSStub_1516 {
  strings:
    $key_1516 = { 41 7e [2] 35 66 [2] 72 64 [2] 35 75 [2] 7b 79 [2] 77 73 [2] 60 78 [2] 7b 36 [2] 46 }

  condition:
    any of them
}