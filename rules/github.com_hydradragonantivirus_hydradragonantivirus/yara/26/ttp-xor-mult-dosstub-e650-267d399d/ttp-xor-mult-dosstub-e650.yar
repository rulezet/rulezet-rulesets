rule TTP_XOR_MULT_DOSStub_e650 {
  strings:
    $key_e650 = { b2 38 [2] c6 20 [2] 81 22 [2] c6 33 [2] 88 3f [2] 84 35 [2] 93 3e [2] 88 70 [2] b5 }

  condition:
    any of them
}