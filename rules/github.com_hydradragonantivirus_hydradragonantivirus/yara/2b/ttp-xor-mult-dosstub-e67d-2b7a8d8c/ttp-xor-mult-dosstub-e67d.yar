rule TTP_XOR_MULT_DOSStub_e67d {
  strings:
    $key_e67d = { b2 15 [2] c6 0d [2] 81 0f [2] c6 1e [2] 88 12 [2] 84 18 [2] 93 13 [2] 88 5d [2] b5 }

  condition:
    any of them
}