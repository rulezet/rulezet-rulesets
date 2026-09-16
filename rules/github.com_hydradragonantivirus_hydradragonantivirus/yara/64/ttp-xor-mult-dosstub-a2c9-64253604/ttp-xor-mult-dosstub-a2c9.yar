rule TTP_XOR_MULT_DOSStub_a2c9 {
  strings:
    $key_a2c9 = { f6 a1 [2] 82 b9 [2] c5 bb [2] 82 aa [2] cc a6 [2] c0 ac [2] d7 a7 [2] cc e9 [2] f1 }

  condition:
    any of them
}