rule TTP_XOR_MULT_DOSStub_6ce1 {
  strings:
    $key_6ce1 = { 38 89 [2] 4c 91 [2] 0b 93 [2] 4c 82 [2] 02 8e [2] 0e 84 [2] 19 8f [2] 02 c1 [2] 3f }

  condition:
    any of them
}