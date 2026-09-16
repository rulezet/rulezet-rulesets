rule TTP_XOR_MULT_DOSStub_2037 {
  strings:
    $key_2037 = { 74 5f [2] 00 47 [2] 47 45 [2] 00 54 [2] 4e 58 [2] 42 52 [2] 55 59 [2] 4e 17 [2] 73 }

  condition:
    any of them
}