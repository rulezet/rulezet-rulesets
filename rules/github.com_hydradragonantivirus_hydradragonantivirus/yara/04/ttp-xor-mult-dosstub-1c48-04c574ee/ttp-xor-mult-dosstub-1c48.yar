rule TTP_XOR_MULT_DOSStub_1c48 {
  strings:
    $key_1c48 = { 48 20 [2] 3c 38 [2] 7b 3a [2] 3c 2b [2] 72 27 [2] 7e 2d [2] 69 26 [2] 72 68 [2] 4f }

  condition:
    any of them
}