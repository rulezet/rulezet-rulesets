rule TTP_XOR_MULT_DOSStub_4a09 {
  strings:
    $key_4a09 = { 1e 61 [2] 6a 79 [2] 2d 7b [2] 6a 6a [2] 24 66 [2] 28 6c [2] 3f 67 [2] 24 29 [2] 19 }

  condition:
    any of them
}