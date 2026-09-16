rule TTP_XOR_MULT_DOSStub_537f {
  strings:
    $key_537f = { 07 17 [2] 73 0f [2] 34 0d [2] 73 1c [2] 3d 10 [2] 31 1a [2] 26 11 [2] 3d 5f [2] 00 }

  condition:
    any of them
}