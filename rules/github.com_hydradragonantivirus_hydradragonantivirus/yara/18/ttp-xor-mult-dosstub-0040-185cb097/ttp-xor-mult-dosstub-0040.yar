rule TTP_XOR_MULT_DOSStub_0040 {
  strings:
    $key_0040 = { 54 28 [2] 20 30 [2] 67 32 [2] 20 23 [2] 6e 2f [2] 62 25 [2] 75 2e [2] 6e 60 [2] 53 }

  condition:
    any of them
}