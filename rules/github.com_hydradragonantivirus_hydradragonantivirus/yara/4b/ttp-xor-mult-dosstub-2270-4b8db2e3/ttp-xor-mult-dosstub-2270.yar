rule TTP_XOR_MULT_DOSStub_2270 {
  strings:
    $key_2270 = { 76 18 [2] 02 00 [2] 45 02 [2] 02 13 [2] 4c 1f [2] 40 15 [2] 57 1e [2] 4c 50 [2] 71 }

  condition:
    any of them
}