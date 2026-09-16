rule TTP_XOR_MULT_DOSStub_6cf6 {
  strings:
    $key_6cf6 = { 38 9e [2] 4c 86 [2] 0b 84 [2] 4c 95 [2] 02 99 [2] 0e 93 [2] 19 98 [2] 02 d6 [2] 3f }

  condition:
    any of them
}