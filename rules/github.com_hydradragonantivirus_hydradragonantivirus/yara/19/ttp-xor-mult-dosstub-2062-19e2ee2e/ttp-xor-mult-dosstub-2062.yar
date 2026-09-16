rule TTP_XOR_MULT_DOSStub_2062 {
  strings:
    $key_2062 = { 74 0a [2] 00 12 [2] 47 10 [2] 00 01 [2] 4e 0d [2] 42 07 [2] 55 0c [2] 4e 42 [2] 73 }

  condition:
    any of them
}