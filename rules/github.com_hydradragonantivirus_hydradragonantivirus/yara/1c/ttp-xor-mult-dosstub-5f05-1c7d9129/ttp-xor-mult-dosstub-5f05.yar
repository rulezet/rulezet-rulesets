rule TTP_XOR_MULT_DOSStub_5f05 {
  strings:
    $key_5f05 = { 0b 6d [2] 7f 75 [2] 38 77 [2] 7f 66 [2] 31 6a [2] 3d 60 [2] 2a 6b [2] 31 25 [2] 0c }

  condition:
    any of them
}