rule TTP_XOR_MULT_DOSStub_e6e7 {
  strings:
    $key_e6e7 = { b2 8f [2] c6 97 [2] 81 95 [2] c6 84 [2] 88 88 [2] 84 82 [2] 93 89 [2] 88 c7 [2] b5 }

  condition:
    any of them
}