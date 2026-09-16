rule TTP_XOR_MULT_DOSStub_d6de {
  strings:
    $key_d6de = { 82 b6 [2] f6 ae [2] b1 ac [2] f6 bd [2] b8 b1 [2] b4 bb [2] a3 b0 [2] b8 fe [2] 85 }

  condition:
    any of them
}