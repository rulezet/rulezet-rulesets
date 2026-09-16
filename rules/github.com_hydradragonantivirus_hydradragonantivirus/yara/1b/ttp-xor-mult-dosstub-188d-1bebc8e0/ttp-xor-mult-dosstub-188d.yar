rule TTP_XOR_MULT_DOSStub_188d {
  strings:
    $key_188d = { 4c e5 [2] 38 fd [2] 7f ff [2] 38 ee [2] 76 e2 [2] 7a e8 [2] 6d e3 [2] 76 ad [2] 4b }

  condition:
    any of them
}