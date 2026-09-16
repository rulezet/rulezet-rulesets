rule TTP_XOR_MULT_DOSStub_7852 {
  strings:
    $key_7852 = { 2c 3a [2] 58 22 [2] 1f 20 [2] 58 31 [2] 16 3d [2] 1a 37 [2] 0d 3c [2] 16 72 [2] 2b }

  condition:
    any of them
}