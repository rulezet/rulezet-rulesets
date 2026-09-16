rule TTP_XOR_MULT_DOSStub_0270 {
  strings:
    $key_0270 = { 56 18 [2] 22 00 [2] 65 02 [2] 22 13 [2] 6c 1f [2] 60 15 [2] 77 1e [2] 6c 50 [2] 51 }

  condition:
    any of them
}