rule TTP_XOR_MULT_DOSStub_1c43 {
  strings:
    $key_1c43 = { 48 2b [2] 3c 33 [2] 7b 31 [2] 3c 20 [2] 72 2c [2] 7e 26 [2] 69 2d [2] 72 63 [2] 4f }

  condition:
    any of them
}