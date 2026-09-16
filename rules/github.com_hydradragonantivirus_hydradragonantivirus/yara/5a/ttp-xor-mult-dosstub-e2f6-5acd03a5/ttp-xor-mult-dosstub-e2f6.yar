rule TTP_XOR_MULT_DOSStub_e2f6 {
  strings:
    $key_e2f6 = { b6 9e [2] c2 86 [2] 85 84 [2] c2 95 [2] 8c 99 [2] 80 93 [2] 97 98 [2] 8c d6 [2] b1 }

  condition:
    any of them
}