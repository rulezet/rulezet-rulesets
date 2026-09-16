rule TTP_XOR_MULT_DOSStub_53f8 {
  strings:
    $key_53f8 = { 07 90 [2] 73 88 [2] 34 8a [2] 73 9b [2] 3d 97 [2] 31 9d [2] 26 96 [2] 3d d8 [2] 00 }

  condition:
    any of them
}