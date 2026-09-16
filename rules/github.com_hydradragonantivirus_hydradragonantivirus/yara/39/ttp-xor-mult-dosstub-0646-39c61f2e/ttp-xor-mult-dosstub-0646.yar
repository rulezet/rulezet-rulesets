rule TTP_XOR_MULT_DOSStub_0646 {
  strings:
    $key_0646 = { 52 2e [2] 26 36 [2] 61 34 [2] 26 25 [2] 68 29 [2] 64 23 [2] 73 28 [2] 68 66 [2] 55 }

  condition:
    any of them
}