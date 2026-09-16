rule TTP_XOR_MULT_DOSStub_e4f0 {
  strings:
    $key_e4f0 = { b0 98 [2] c4 80 [2] 83 82 [2] c4 93 [2] 8a 9f [2] 86 95 [2] 91 9e [2] 8a d0 [2] b7 }

  condition:
    any of them
}