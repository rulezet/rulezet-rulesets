rule TTP_XOR_MULT_DOSStub_a1b1 {
  strings:
    $key_a1b1 = { f5 d9 [2] 81 c1 [2] c6 c3 [2] 81 d2 [2] cf de [2] c3 d4 [2] d4 df [2] cf 91 [2] f2 }

  condition:
    any of them
}