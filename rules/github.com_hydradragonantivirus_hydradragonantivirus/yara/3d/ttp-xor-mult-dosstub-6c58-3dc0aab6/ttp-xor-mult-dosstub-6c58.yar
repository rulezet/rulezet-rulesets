rule TTP_XOR_MULT_DOSStub_6c58 {
  strings:
    $key_6c58 = { 38 30 [2] 4c 28 [2] 0b 2a [2] 4c 3b [2] 02 37 [2] 0e 3d [2] 19 36 [2] 02 78 [2] 3f }

  condition:
    any of them
}