rule TTP_XOR_MULT_DOSStub_4a64 {
  strings:
    $key_4a64 = { 1e 0c [2] 6a 14 [2] 2d 16 [2] 6a 07 [2] 24 0b [2] 28 01 [2] 3f 0a [2] 24 44 [2] 19 }

  condition:
    any of them
}