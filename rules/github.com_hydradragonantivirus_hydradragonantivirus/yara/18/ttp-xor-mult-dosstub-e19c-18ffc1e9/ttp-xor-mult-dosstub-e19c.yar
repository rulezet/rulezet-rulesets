rule TTP_XOR_MULT_DOSStub_e19c {
  strings:
    $key_e19c = { b5 f4 [2] c1 ec [2] 86 ee [2] c1 ff [2] 8f f3 [2] 83 f9 [2] 94 f2 [2] 8f bc [2] b2 }

  condition:
    any of them
}