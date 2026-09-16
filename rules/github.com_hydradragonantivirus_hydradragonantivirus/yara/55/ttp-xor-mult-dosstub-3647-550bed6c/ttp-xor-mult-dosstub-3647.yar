rule TTP_XOR_MULT_DOSStub_3647 {
  strings:
    $key_3647 = { 62 2f [2] 16 37 [2] 51 35 [2] 16 24 [2] 58 28 [2] 54 22 [2] 43 29 [2] 58 67 [2] 65 }

  condition:
    any of them
}