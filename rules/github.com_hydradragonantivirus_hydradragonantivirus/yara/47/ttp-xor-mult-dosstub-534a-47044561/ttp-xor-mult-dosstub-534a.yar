rule TTP_XOR_MULT_DOSStub_534a {
  strings:
    $key_534a = { 07 22 [2] 73 3a [2] 34 38 [2] 73 29 [2] 3d 25 [2] 31 2f [2] 26 24 [2] 3d 6a [2] 00 }

  condition:
    any of them
}