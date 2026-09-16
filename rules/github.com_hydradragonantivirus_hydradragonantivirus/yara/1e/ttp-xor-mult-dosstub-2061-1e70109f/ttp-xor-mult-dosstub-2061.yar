rule TTP_XOR_MULT_DOSStub_2061 {
  strings:
    $key_2061 = { 74 09 [2] 00 11 [2] 47 13 [2] 00 02 [2] 4e 0e [2] 42 04 [2] 55 0f [2] 4e 41 [2] 73 }

  condition:
    any of them
}