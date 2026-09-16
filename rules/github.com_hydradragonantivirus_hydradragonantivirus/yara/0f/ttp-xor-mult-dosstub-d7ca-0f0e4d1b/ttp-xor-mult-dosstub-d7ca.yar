rule TTP_XOR_MULT_DOSStub_d7ca {
  strings:
    $key_d7ca = { 83 a2 [2] f7 ba [2] b0 b8 [2] f7 a9 [2] b9 a5 [2] b5 af [2] a2 a4 [2] b9 ea [2] 84 }

  condition:
    any of them
}