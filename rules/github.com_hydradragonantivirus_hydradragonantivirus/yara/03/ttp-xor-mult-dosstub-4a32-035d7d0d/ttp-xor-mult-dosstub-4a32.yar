rule TTP_XOR_MULT_DOSStub_4a32 {
  strings:
    $key_4a32 = { 1e 5a [2] 6a 42 [2] 2d 40 [2] 6a 51 [2] 24 5d [2] 28 57 [2] 3f 5c [2] 24 12 [2] 19 }

  condition:
    any of them
}