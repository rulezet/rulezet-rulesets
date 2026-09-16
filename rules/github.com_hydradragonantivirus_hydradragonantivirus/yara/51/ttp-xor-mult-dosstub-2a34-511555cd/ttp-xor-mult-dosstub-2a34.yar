rule TTP_XOR_MULT_DOSStub_2a34 {
  strings:
    $key_2a34 = { 7e 5c [2] 0a 44 [2] 4d 46 [2] 0a 57 [2] 44 5b [2] 48 51 [2] 5f 5a [2] 44 14 [2] 79 }

  condition:
    any of them
}