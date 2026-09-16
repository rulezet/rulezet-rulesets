rule TTP_XOR_MULT_DOSStub_2a05 {
  strings:
    $key_2a05 = { 7e 6d [2] 0a 75 [2] 4d 77 [2] 0a 66 [2] 44 6a [2] 48 60 [2] 5f 6b [2] 44 25 [2] 79 }

  condition:
    any of them
}