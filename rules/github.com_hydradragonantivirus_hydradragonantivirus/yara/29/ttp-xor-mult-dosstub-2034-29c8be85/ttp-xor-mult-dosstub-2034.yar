rule TTP_XOR_MULT_DOSStub_2034 {
  strings:
    $key_2034 = { 74 5c [2] 00 44 [2] 47 46 [2] 00 57 [2] 4e 5b [2] 42 51 [2] 55 5a [2] 4e 14 [2] 73 }

  condition:
    any of them
}