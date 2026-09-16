rule TTP_XOR_MULT_DOSStub_0440 {
  strings:
    $key_0440 = { 50 28 [2] 24 30 [2] 63 32 [2] 24 23 [2] 6a 2f [2] 66 25 [2] 71 2e [2] 6a 60 [2] 57 }

  condition:
    any of them
}