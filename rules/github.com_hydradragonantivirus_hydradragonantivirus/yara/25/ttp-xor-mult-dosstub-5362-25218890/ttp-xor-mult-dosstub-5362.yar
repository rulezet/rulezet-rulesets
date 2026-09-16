rule TTP_XOR_MULT_DOSStub_5362 {
  strings:
    $key_5362 = { 07 0a [2] 73 12 [2] 34 10 [2] 73 01 [2] 3d 0d [2] 31 07 [2] 26 0c [2] 3d 42 [2] 00 }

  condition:
    any of them
}