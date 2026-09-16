rule TTP_XOR_MULT_DOSStub_6c02 {
  strings:
    $key_6c02 = { 38 6a [2] 4c 72 [2] 0b 70 [2] 4c 61 [2] 02 6d [2] 0e 67 [2] 19 6c [2] 02 22 [2] 3f }

  condition:
    any of them
}