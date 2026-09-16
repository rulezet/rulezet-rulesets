rule TTP_XOR_MULT_DOSStub_6c45 {
  strings:
    $key_6c45 = { 38 2d [2] 4c 35 [2] 0b 37 [2] 4c 26 [2] 02 2a [2] 0e 20 [2] 19 2b [2] 02 65 [2] 3f }

  condition:
    any of them
}