rule TTP_XOR_MULT_DOSStub_3f05 {
  strings:
    $key_3f05 = { 6b 6d [2] 1f 75 [2] 58 77 [2] 1f 66 [2] 51 6a [2] 5d 60 [2] 4a 6b [2] 51 25 [2] 6c }

  condition:
    any of them
}