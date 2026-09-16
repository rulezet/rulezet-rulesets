rule TTP_XOR_MULT_DOSStub_5516 {
  strings:
    $key_5516 = { 01 7e [2] 75 66 [2] 32 64 [2] 75 75 [2] 3b 79 [2] 37 73 [2] 20 78 [2] 3b 36 [2] 06 }

  condition:
    any of them
}