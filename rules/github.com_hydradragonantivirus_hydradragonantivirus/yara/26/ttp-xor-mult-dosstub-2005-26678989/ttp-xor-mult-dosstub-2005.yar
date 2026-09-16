rule TTP_XOR_MULT_DOSStub_2005 {
  strings:
    $key_2005 = { 74 6d [2] 00 75 [2] 47 77 [2] 00 66 [2] 4e 6a [2] 42 60 [2] 55 6b [2] 4e 25 [2] 73 }

  condition:
    any of them
}