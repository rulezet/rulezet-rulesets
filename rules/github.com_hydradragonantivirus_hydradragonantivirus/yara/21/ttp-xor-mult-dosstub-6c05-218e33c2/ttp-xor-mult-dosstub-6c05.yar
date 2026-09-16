rule TTP_XOR_MULT_DOSStub_6c05 {
  strings:
    $key_6c05 = { 38 6d [2] 4c 75 [2] 0b 77 [2] 4c 66 [2] 02 6a [2] 0e 60 [2] 19 6b [2] 02 25 [2] 3f }

  condition:
    any of them
}