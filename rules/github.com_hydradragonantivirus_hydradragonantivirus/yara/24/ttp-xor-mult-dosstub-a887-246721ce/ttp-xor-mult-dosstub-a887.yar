rule TTP_XOR_MULT_DOSStub_a887 {
  strings:
    $key_a887 = { fc ef [2] 88 f7 [2] cf f5 [2] 88 e4 [2] c6 e8 [2] ca e2 [2] dd e9 [2] c6 a7 [2] fb }

  condition:
    any of them
}