rule TTP_XOR_MULT_DOSStub_e18d {
  strings:
    $key_e18d = { b5 e5 [2] c1 fd [2] 86 ff [2] c1 ee [2] 8f e2 [2] 83 e8 [2] 94 e3 [2] 8f ad [2] b2 }

  condition:
    any of them
}