rule TTP_XOR_MULT_DOSStub_2a59 {
  strings:
    $key_2a59 = { 7e 31 [2] 0a 29 [2] 4d 2b [2] 0a 3a [2] 44 36 [2] 48 3c [2] 5f 37 [2] 44 79 [2] 79 }

  condition:
    any of them
}