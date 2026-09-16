rule TTP_XOR_MULT_DOSStub_4a04 {
  strings:
    $key_4a04 = { 1e 6c [2] 6a 74 [2] 2d 76 [2] 6a 67 [2] 24 6b [2] 28 61 [2] 3f 6a [2] 24 24 [2] 19 }

  condition:
    any of them
}