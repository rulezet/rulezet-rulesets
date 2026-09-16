rule TTP_XOR_MULT_DOSStub_1c52 {
  strings:
    $key_1c52 = { 48 3a [2] 3c 22 [2] 7b 20 [2] 3c 31 [2] 72 3d [2] 7e 37 [2] 69 3c [2] 72 72 [2] 4f }

  condition:
    any of them
}