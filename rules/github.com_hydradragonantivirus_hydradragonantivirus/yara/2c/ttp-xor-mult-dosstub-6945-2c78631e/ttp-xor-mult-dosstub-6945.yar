rule TTP_XOR_MULT_DOSStub_6945 {
  strings:
    $key_6945 = { 3d 2d [2] 49 35 [2] 0e 37 [2] 49 26 [2] 07 2a [2] 0b 20 [2] 1c 2b [2] 07 65 [2] 3a }

  condition:
    any of them
}