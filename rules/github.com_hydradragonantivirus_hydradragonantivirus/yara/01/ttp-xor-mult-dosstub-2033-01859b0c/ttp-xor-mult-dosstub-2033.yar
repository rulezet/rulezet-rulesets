rule TTP_XOR_MULT_DOSStub_2033 {
  strings:
    $key_2033 = { 74 5b [2] 00 43 [2] 47 41 [2] 00 50 [2] 4e 5c [2] 42 56 [2] 55 5d [2] 4e 13 [2] 73 }

  condition:
    any of them
}