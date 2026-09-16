rule TTP_XOR_MULT_DOSStub_c1cb {
  strings:
    $key_c1cb = { 95 a3 [2] e1 bb [2] a6 b9 [2] e1 a8 [2] af a4 [2] a3 ae [2] b4 a5 [2] af eb [2] 92 }

  condition:
    any of them
}