rule TTP_XOR_MULT_DOSStub_e4e1 {
  strings:
    $key_e4e1 = { b0 89 [2] c4 91 [2] 83 93 [2] c4 82 [2] 8a 8e [2] 86 84 [2] 91 8f [2] 8a c1 [2] b7 }

  condition:
    any of them
}