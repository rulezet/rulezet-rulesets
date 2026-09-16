rule TTP_XOR_MULT_DOSStub_1c69 {
  strings:
    $key_1c69 = { 48 01 [2] 3c 19 [2] 7b 1b [2] 3c 0a [2] 72 06 [2] 7e 0c [2] 69 07 [2] 72 49 [2] 4f }

  condition:
    any of them
}