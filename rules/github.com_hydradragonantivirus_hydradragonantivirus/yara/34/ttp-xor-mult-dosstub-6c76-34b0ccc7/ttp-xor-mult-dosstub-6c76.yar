rule TTP_XOR_MULT_DOSStub_6c76 {
  strings:
    $key_6c76 = { 38 1e [2] 4c 06 [2] 0b 04 [2] 4c 15 [2] 02 19 [2] 0e 13 [2] 19 18 [2] 02 56 [2] 3f }

  condition:
    any of them
}