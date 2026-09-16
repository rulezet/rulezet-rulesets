rule TTP_XOR_MULT_DOSStub_1c45 {
  strings:
    $key_1c45 = { 48 2d [2] 3c 35 [2] 7b 37 [2] 3c 26 [2] 72 2a [2] 7e 20 [2] 69 2b [2] 72 65 [2] 4f }

  condition:
    any of them
}