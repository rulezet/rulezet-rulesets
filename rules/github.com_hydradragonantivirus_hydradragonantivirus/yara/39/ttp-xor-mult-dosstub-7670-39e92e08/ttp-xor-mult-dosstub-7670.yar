rule TTP_XOR_MULT_DOSStub_7670 {
  strings:
    $key_7670 = { 22 18 [2] 56 00 [2] 11 02 [2] 56 13 [2] 18 1f [2] 14 15 [2] 03 1e [2] 18 50 [2] 25 }

  condition:
    any of them
}