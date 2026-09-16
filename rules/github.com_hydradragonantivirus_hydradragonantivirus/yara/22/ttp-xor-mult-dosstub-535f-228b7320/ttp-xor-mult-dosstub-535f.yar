rule TTP_XOR_MULT_DOSStub_535f {
  strings:
    $key_535f = { 07 37 [2] 73 2f [2] 34 2d [2] 73 3c [2] 3d 30 [2] 31 3a [2] 26 31 [2] 3d 7f [2] 00 }

  condition:
    any of them
}