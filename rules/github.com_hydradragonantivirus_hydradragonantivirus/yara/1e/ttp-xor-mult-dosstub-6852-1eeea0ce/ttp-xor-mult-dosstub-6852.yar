rule TTP_XOR_MULT_DOSStub_6852 {
  strings:
    $key_6852 = { 3c 3a [2] 48 22 [2] 0f 20 [2] 48 31 [2] 06 3d [2] 0a 37 [2] 1d 3c [2] 06 72 [2] 3b }

  condition:
    any of them
}