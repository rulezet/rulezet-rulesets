rule TTP_XOR_MULT_DOSStub_2077 {
  strings:
    $key_2077 = { 74 1f [2] 00 07 [2] 47 05 [2] 00 14 [2] 4e 18 [2] 42 12 [2] 55 19 [2] 4e 57 [2] 73 }

  condition:
    any of them
}