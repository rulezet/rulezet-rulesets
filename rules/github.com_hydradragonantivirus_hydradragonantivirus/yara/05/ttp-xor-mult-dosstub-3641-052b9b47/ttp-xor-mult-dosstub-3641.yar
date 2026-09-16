rule TTP_XOR_MULT_DOSStub_3641 {
  strings:
    $key_3641 = { 62 29 [2] 16 31 [2] 51 33 [2] 16 22 [2] 58 2e [2] 54 24 [2] 43 2f [2] 58 61 [2] 65 }

  condition:
    any of them
}