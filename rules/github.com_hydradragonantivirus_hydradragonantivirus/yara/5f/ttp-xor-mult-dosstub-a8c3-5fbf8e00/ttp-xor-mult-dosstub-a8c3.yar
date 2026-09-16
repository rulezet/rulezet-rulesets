rule TTP_XOR_MULT_DOSStub_a8c3 {
  strings:
    $key_a8c3 = { fc ab [2] 88 b3 [2] cf b1 [2] 88 a0 [2] c6 ac [2] ca a6 [2] dd ad [2] c6 e3 [2] fb }

  condition:
    any of them
}