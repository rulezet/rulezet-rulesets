rule TTP_XOR_MULT_DOSStub_3070 {
  strings:
    $key_3070 = { 64 18 [2] 10 00 [2] 57 02 [2] 10 13 [2] 5e 1f [2] 52 15 [2] 45 1e [2] 5e 50 [2] 63 }

  condition:
    any of them
}