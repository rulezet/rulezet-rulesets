rule TTP_XOR_MULT_DOSStub_3105 {
  strings:
    $key_3105 = { 65 6d [2] 11 75 [2] 56 77 [2] 11 66 [2] 5f 6a [2] 53 60 [2] 44 6b [2] 5f 25 [2] 62 }

  condition:
    any of them
}