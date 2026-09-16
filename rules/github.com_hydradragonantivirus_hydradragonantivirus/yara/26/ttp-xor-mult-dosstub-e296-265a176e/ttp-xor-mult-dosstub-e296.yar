rule TTP_XOR_MULT_DOSStub_e296 {
  strings:
    $key_e296 = { b6 fe [2] c2 e6 [2] 85 e4 [2] c2 f5 [2] 8c f9 [2] 80 f3 [2] 97 f8 [2] 8c b6 [2] b1 }

  condition:
    any of them
}