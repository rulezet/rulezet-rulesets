rule TTP_XOR_MULT_DOSStub_0246 {
  strings:
    $key_0246 = { 56 2e [2] 22 36 [2] 65 34 [2] 22 25 [2] 6c 29 [2] 60 23 [2] 77 28 [2] 6c 66 [2] 51 }

  condition:
    any of them
}