rule TTP_XOR_MULT_DOSStub_b2de {
  strings:
    $key_b2de = { e6 b6 [2] 92 ae [2] d5 ac [2] 92 bd [2] dc b1 [2] d0 bb [2] c7 b0 [2] dc fe [2] e1 }

  condition:
    any of them
}