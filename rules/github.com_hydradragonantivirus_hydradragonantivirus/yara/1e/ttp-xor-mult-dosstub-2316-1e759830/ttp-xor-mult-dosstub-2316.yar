rule TTP_XOR_MULT_DOSStub_2316 {
  strings:
    $key_2316 = { 77 7e [2] 03 66 [2] 44 64 [2] 03 75 [2] 4d 79 [2] 41 73 [2] 56 78 [2] 4d 36 [2] 70 }

  condition:
    any of them
}