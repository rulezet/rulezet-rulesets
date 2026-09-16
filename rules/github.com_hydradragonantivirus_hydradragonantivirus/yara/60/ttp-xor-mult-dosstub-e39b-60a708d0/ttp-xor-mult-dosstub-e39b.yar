rule TTP_XOR_MULT_DOSStub_e39b {
  strings:
    $key_e39b = { b7 f3 [2] c3 eb [2] 84 e9 [2] c3 f8 [2] 8d f4 [2] 81 fe [2] 96 f5 [2] 8d bb [2] b0 }

  condition:
    any of them
}