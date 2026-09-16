rule TTP_XOR_MULT_DOSStub_0070 {
  strings:
    $key_0070 = { 54 18 [2] 20 00 [2] 67 02 [2] 20 13 [2] 6e 1f [2] 62 15 [2] 75 1e [2] 6e 50 [2] 53 }

  condition:
    any of them
}