rule TTP_XOR_MULT_DOSStub_2041 {
  strings:
    $key_2041 = { 74 29 [2] 00 31 [2] 47 33 [2] 00 22 [2] 4e 2e [2] 42 24 [2] 55 2f [2] 4e 61 [2] 73 }

  condition:
    any of them
}