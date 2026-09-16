rule TTP_XOR_MULT_DOSStub_4a79 {
  strings:
    $key_4a79 = { 1e 11 [2] 6a 09 [2] 2d 0b [2] 6a 1a [2] 24 16 [2] 28 1c [2] 3f 17 [2] 24 59 [2] 19 }

  condition:
    any of them
}