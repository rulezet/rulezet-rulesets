rule TTP_XOR_MULT_DOSStub_e6e1 {
  strings:
    $key_e6e1 = { b2 89 [2] c6 91 [2] 81 93 [2] c6 82 [2] 88 8e [2] 84 84 [2] 93 8f [2] 88 c1 [2] b5 }

  condition:
    any of them
}