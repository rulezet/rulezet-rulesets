rule TTP_XOR_MULT_DOSStub_2047 {
  strings:
    $key_2047 = { 74 2f [2] 00 37 [2] 47 35 [2] 00 24 [2] 4e 28 [2] 42 22 [2] 55 29 [2] 4e 67 [2] 73 }

  condition:
    any of them
}