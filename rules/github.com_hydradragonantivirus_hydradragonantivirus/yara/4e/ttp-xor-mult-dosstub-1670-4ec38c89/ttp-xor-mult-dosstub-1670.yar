rule TTP_XOR_MULT_DOSStub_1670 {
  strings:
    $key_1670 = { 42 18 [2] 36 00 [2] 71 02 [2] 36 13 [2] 78 1f [2] 74 15 [2] 63 1e [2] 78 50 [2] 45 }

  condition:
    any of them
}