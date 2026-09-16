rule TTP_XOR_MULT_DOSStub_2070 {
  strings:
    $key_2070 = { 74 18 [2] 00 00 [2] 47 02 [2] 00 13 [2] 4e 1f [2] 42 15 [2] 55 1e [2] 4e 50 [2] 73 }

  condition:
    any of them
}