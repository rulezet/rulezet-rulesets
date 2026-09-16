rule TTP_XOR_MULT_DOSStub_5852 {
  strings:
    $key_5852 = { 0c 3a [2] 78 22 [2] 3f 20 [2] 78 31 [2] 36 3d [2] 3a 37 [2] 2d 3c [2] 36 72 [2] 0b }

  condition:
    any of them
}