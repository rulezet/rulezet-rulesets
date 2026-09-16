rule TTP_XOR_MULT_DOSStub_1705 {
  strings:
    $key_1705 = { 43 6d [2] 37 75 [2] 70 77 [2] 37 66 [2] 79 6a [2] 75 60 [2] 62 6b [2] 79 25 [2] 44 }

  condition:
    any of them
}