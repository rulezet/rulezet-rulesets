rule TTP_XOR_MULT_DOSStub_2017 {
  strings:
    $key_2017 = { 74 7f [2] 00 67 [2] 47 65 [2] 00 74 [2] 4e 78 [2] 42 72 [2] 55 79 [2] 4e 37 [2] 73 }

  condition:
    any of them
}