rule TTP_XOR_MULT_DOSStub_e0ca {
  strings:
    $key_e0ca = { b4 a2 [2] c0 ba [2] 87 b8 [2] c0 a9 [2] 8e a5 [2] 82 af [2] 95 a4 [2] 8e ea [2] b3 }

  condition:
    any of them
}