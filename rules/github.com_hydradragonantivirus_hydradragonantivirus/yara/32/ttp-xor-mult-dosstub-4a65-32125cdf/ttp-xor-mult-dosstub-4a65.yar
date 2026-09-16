rule TTP_XOR_MULT_DOSStub_4a65 {
  strings:
    $key_4a65 = { 1e 0d [2] 6a 15 [2] 2d 17 [2] 6a 06 [2] 24 0a [2] 28 00 [2] 3f 0b [2] 24 45 [2] 19 }

  condition:
    any of them
}