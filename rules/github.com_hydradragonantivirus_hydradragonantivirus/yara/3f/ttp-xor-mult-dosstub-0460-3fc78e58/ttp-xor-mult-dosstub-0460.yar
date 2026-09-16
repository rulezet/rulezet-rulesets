rule TTP_XOR_MULT_DOSStub_0460 {
  strings:
    $key_0460 = { 50 08 [2] 24 10 [2] 63 12 [2] 24 03 [2] 6a 0f [2] 66 05 [2] 71 0e [2] 6a 40 [2] 57 }

  condition:
    any of them
}