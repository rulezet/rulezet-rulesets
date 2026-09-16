rule TTP_XOR_MULT_DOSStub_0105 {
  strings:
    $key_0105 = { 55 6d [2] 21 75 [2] 66 77 [2] 21 66 [2] 6f 6a [2] 63 60 [2] 74 6b [2] 6f 25 [2] 52 }

  condition:
    any of them
}