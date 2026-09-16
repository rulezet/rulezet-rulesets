rule TTP_XOR_MULT_DOSStub_e4f6 {
  strings:
    $key_e4f6 = { b0 9e [2] c4 86 [2] 83 84 [2] c4 95 [2] 8a 99 [2] 86 93 [2] 91 98 [2] 8a d6 [2] b7 }

  condition:
    any of them
}