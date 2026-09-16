rule TTP_XOR_MULT_DOSStub_2c55 {
  strings:
    $key_2c55 = { 78 3d [2] 0c 25 [2] 4b 27 [2] 0c 36 [2] 42 3a [2] 4e 30 [2] 59 3b [2] 42 75 [2] 7f }

  condition:
    any of them
}