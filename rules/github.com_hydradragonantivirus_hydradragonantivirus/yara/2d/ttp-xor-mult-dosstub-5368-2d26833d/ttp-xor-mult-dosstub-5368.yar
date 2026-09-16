rule TTP_XOR_MULT_DOSStub_5368 {
  strings:
    $key_5368 = { 07 00 [2] 73 18 [2] 34 1a [2] 73 0b [2] 3d 07 [2] 31 0d [2] 26 06 [2] 3d 48 [2] 00 }

  condition:
    any of them
}