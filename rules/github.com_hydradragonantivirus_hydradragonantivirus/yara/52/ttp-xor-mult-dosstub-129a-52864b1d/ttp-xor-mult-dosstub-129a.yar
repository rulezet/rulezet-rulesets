rule TTP_XOR_MULT_DOSStub_129a {
  strings:
    $key_129a = { 46 f2 [2] 32 ea [2] 75 e8 [2] 32 f9 [2] 7c f5 [2] 70 ff [2] 67 f4 [2] 7c ba [2] 41 }

  condition:
    any of them
}