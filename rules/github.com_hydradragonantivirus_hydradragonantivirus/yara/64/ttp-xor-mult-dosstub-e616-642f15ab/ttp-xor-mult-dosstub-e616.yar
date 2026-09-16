rule TTP_XOR_MULT_DOSStub_e616 {
  strings:
    $key_e616 = { b2 7e [2] c6 66 [2] 81 64 [2] c6 75 [2] 88 79 [2] 84 73 [2] 93 78 [2] 88 36 [2] b5 }

  condition:
    any of them
}