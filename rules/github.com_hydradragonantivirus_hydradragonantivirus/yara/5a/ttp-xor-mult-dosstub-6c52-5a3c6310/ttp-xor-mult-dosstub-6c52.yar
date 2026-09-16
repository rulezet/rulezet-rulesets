rule TTP_XOR_MULT_DOSStub_6c52 {
  strings:
    $key_6c52 = { 38 3a [2] 4c 22 [2] 0b 20 [2] 4c 31 [2] 02 3d [2] 0e 37 [2] 19 3c [2] 02 72 [2] 3f }

  condition:
    any of them
}