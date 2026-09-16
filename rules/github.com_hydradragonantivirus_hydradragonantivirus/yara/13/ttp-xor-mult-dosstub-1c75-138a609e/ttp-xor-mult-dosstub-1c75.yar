rule TTP_XOR_MULT_DOSStub_1c75 {
  strings:
    $key_1c75 = { 48 1d [2] 3c 05 [2] 7b 07 [2] 3c 16 [2] 72 1a [2] 7e 10 [2] 69 1b [2] 72 55 [2] 4f }

  condition:
    any of them
}