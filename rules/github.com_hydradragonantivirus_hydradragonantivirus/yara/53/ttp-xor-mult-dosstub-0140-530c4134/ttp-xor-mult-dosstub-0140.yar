rule TTP_XOR_MULT_DOSStub_0140 {
  strings:
    $key_0140 = { 55 28 [2] 21 30 [2] 66 32 [2] 21 23 [2] 6f 2f [2] 63 25 [2] 74 2e [2] 6f 60 [2] 52 }

  condition:
    any of them
}