rule TTP_XOR_MULT_DOSStub_2c52 {
  strings:
    $key_2c52 = { 78 3a [2] 0c 22 [2] 4b 20 [2] 0c 31 [2] 42 3d [2] 4e 37 [2] 59 3c [2] 42 72 [2] 7f }

  condition:
    any of them
}