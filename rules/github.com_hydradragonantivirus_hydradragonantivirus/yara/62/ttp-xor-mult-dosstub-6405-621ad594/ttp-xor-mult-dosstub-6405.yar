rule TTP_XOR_MULT_DOSStub_6405 {
  strings:
    $key_6405 = { 30 6d [2] 44 75 [2] 03 77 [2] 44 66 [2] 0a 6a [2] 06 60 [2] 11 6b [2] 0a 25 [2] 37 }

  condition:
    any of them
}