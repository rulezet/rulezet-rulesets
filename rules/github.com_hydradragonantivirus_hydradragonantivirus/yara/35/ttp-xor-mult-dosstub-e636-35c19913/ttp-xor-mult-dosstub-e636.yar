rule TTP_XOR_MULT_DOSStub_e636 {
  strings:
    $key_e636 = { b2 5e [2] c6 46 [2] 81 44 [2] c6 55 [2] 88 59 [2] 84 53 [2] 93 58 [2] 88 16 [2] b5 }

  condition:
    any of them
}