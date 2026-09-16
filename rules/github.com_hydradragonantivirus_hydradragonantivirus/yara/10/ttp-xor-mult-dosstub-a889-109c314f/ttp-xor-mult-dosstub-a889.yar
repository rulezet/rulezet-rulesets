rule TTP_XOR_MULT_DOSStub_a889 {
  strings:
    $key_a889 = { fc e1 [2] 88 f9 [2] cf fb [2] 88 ea [2] c6 e6 [2] ca ec [2] dd e7 [2] c6 a9 [2] fb }

  condition:
    any of them
}