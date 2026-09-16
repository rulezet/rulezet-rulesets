rule TTP_XOR_MULT_DOSStub_d78d {
  strings:
    $key_d78d = { 83 e5 [2] f7 fd [2] b0 ff [2] f7 ee [2] b9 e2 [2] b5 e8 [2] a2 e3 [2] b9 ad [2] 84 }

  condition:
    any of them
}