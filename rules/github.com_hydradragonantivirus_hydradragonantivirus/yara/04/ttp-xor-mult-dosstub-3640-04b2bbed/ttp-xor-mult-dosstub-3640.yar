rule TTP_XOR_MULT_DOSStub_3640 {
  strings:
    $key_3640 = { 62 28 [2] 16 30 [2] 51 32 [2] 16 23 [2] 58 2f [2] 54 25 [2] 43 2e [2] 58 60 [2] 65 }

  condition:
    any of them
}