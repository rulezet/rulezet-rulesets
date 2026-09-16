rule TTP_XOR_MULT_DOSStub_3656 {
  strings:
    $key_3656 = { 62 3e [2] 16 26 [2] 51 24 [2] 16 35 [2] 58 39 [2] 54 33 [2] 43 38 [2] 58 76 [2] 65 }

  condition:
    any of them
}