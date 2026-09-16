rule TTP_XOR_MULT_DOSStub_e3cb {
  strings:
    $key_e3cb = { b7 a3 [2] c3 bb [2] 84 b9 [2] c3 a8 [2] 8d a4 [2] 81 ae [2] 96 a5 [2] 8d eb [2] b0 }

  condition:
    any of them
}