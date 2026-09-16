rule TTP_XOR_MULT_DOSStub_7a37 {
  strings:
    $key_7a37 = { 2e 5f [2] 5a 47 [2] 1d 45 [2] 5a 54 [2] 14 58 [2] 18 52 [2] 0f 59 [2] 14 17 [2] 29 }

  condition:
    any of them
}