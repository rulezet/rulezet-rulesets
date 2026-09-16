rule TTP_XOR_MULT_DOSStub_1d5f {
  strings:
    $key_1d5f = { 49 37 [2] 3d 2f [2] 7a 2d [2] 3d 3c [2] 73 30 [2] 7f 3a [2] 68 31 [2] 73 7f [2] 4e }

  condition:
    any of them
}