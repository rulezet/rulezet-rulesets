rule TTP_XOR_MULT_DOSStub_0846 {
  strings:
    $key_0846 = { 5c 2e [2] 28 36 [2] 6f 34 [2] 28 25 [2] 66 29 [2] 6a 23 [2] 7d 28 [2] 66 66 [2] 5b }

  condition:
    any of them
}