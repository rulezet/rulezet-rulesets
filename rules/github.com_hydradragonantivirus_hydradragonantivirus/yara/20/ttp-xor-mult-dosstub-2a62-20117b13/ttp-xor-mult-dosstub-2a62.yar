rule TTP_XOR_MULT_DOSStub_2a62 {
  strings:
    $key_2a62 = { 7e 0a [2] 0a 12 [2] 4d 10 [2] 0a 01 [2] 44 0d [2] 48 07 [2] 5f 0c [2] 44 42 [2] 79 }

  condition:
    any of them
}