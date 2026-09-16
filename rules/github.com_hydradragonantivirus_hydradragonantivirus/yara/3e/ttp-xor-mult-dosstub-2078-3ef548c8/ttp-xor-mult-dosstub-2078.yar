rule TTP_XOR_MULT_DOSStub_2078 {
  strings:
    $key_2078 = { 74 10 [2] 00 08 [2] 47 0a [2] 00 1b [2] 4e 17 [2] 42 1d [2] 55 16 [2] 4e 58 [2] 73 }

  condition:
    any of them
}