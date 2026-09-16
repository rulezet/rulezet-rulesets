rule TTP_XOR_MULT_DOSStub_57c1 {
  strings:
    $key_57c1 = { 03 a9 [2] 77 b1 [2] 30 b3 [2] 77 a2 [2] 39 ae [2] 35 a4 [2] 22 af [2] 39 e1 [2] 04 }

  condition:
    any of them
}