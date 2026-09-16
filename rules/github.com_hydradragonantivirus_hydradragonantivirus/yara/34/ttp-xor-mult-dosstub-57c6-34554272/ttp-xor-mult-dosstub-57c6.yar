rule TTP_XOR_MULT_DOSStub_57c6 {
  strings:
    $key_57c6 = { 03 ae [2] 77 b6 [2] 30 b4 [2] 77 a5 [2] 39 a9 [2] 35 a3 [2] 22 a8 [2] 39 e6 [2] 04 }

  condition:
    any of them
}