rule TTP_XOR_MULT_DOSStub_e78d {
  strings:
    $key_e78d = { b3 e5 [2] c7 fd [2] 80 ff [2] c7 ee [2] 89 e2 [2] 85 e8 [2] 92 e3 [2] 89 ad [2] b4 }

  condition:
    any of them
}