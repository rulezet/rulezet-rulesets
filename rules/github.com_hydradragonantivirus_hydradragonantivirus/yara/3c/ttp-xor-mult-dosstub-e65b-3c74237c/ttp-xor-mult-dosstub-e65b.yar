rule TTP_XOR_MULT_DOSStub_e65b {
  strings:
    $key_e65b = { b2 33 [2] c6 2b [2] 81 29 [2] c6 38 [2] 88 34 [2] 84 3e [2] 93 35 [2] 88 7b [2] b5 }

  condition:
    any of them
}