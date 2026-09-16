rule TTP_XOR_MULT_DOSStub_5430 {
  strings:
    $key_5430 = { 00 58 [2] 74 40 [2] 33 42 [2] 74 53 [2] 3a 5f [2] 36 55 [2] 21 5e [2] 3a 10 [2] 07 }

  condition:
    any of them
}