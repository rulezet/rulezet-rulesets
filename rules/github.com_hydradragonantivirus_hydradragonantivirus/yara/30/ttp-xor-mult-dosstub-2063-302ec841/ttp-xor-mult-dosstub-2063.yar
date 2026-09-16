rule TTP_XOR_MULT_DOSStub_2063 {
  strings:
    $key_2063 = { 74 0b [2] 00 13 [2] 47 11 [2] 00 00 [2] 4e 0c [2] 42 06 [2] 55 0d [2] 4e 43 [2] 73 }

  condition:
    any of them
}