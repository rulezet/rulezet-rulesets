rule TTP_XOR_MULT_DOSStub_6ce2 {
  strings:
    $key_6ce2 = { 38 8a [2] 4c 92 [2] 0b 90 [2] 4c 81 [2] 02 8d [2] 0e 87 [2] 19 8c [2] 02 c2 [2] 3f }

  condition:
    any of them
}