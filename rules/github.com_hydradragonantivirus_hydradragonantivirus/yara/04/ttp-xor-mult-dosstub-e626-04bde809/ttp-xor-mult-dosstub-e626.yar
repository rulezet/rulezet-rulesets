rule TTP_XOR_MULT_DOSStub_e626 {
  strings:
    $key_e626 = { b2 4e [2] c6 56 [2] 81 54 [2] c6 45 [2] 88 49 [2] 84 43 [2] 93 48 [2] 88 06 [2] b5 }

  condition:
    any of them
}