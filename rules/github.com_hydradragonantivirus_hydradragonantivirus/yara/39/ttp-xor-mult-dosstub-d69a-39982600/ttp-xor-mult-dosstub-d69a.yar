rule TTP_XOR_MULT_DOSStub_d69a {
  strings:
    $key_d69a = { 82 f2 [2] f6 ea [2] b1 e8 [2] f6 f9 [2] b8 f5 [2] b4 ff [2] a3 f4 [2] b8 ba [2] 85 }

  condition:
    any of them
}