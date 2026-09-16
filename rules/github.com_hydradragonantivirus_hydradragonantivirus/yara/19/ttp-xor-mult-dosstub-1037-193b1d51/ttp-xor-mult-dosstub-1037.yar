rule TTP_XOR_MULT_DOSStub_1037 {
  strings:
    $key_1037 = { 44 5f [2] 30 47 [2] 77 45 [2] 30 54 [2] 7e 58 [2] 72 52 [2] 65 59 [2] 7e 17 [2] 43 }

  condition:
    any of them
}