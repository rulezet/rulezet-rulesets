rule TTP_XOR_MULT_DOSStub_531a {
  strings:
    $key_531a = { 07 72 [2] 73 6a [2] 34 68 [2] 73 79 [2] 3d 75 [2] 31 7f [2] 26 74 [2] 3d 3a [2] 00 }

  condition:
    any of them
}