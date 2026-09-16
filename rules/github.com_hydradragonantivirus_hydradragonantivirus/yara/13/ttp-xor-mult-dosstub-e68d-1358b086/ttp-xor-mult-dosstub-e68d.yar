rule TTP_XOR_MULT_DOSStub_e68d {
  strings:
    $key_e68d = { b2 e5 [2] c6 fd [2] 81 ff [2] c6 ee [2] 88 e2 [2] 84 e8 [2] 93 e3 [2] 88 ad [2] b5 }

  condition:
    any of them
}