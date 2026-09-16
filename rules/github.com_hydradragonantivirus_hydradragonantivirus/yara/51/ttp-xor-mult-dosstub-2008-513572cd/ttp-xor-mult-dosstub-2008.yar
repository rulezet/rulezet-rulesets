rule TTP_XOR_MULT_DOSStub_2008 {
  strings:
    $key_2008 = { 74 60 [2] 00 78 [2] 47 7a [2] 00 6b [2] 4e 67 [2] 42 6d [2] 55 66 [2] 4e 28 [2] 73 }

  condition:
    any of them
}