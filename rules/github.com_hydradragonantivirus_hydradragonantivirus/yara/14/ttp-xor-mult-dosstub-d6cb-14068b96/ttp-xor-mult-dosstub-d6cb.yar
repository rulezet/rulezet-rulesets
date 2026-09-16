rule TTP_XOR_MULT_DOSStub_d6cb {
  strings:
    $key_d6cb = { 82 a3 [2] f6 bb [2] b1 b9 [2] f6 a8 [2] b8 a4 [2] b4 ae [2] a3 a5 [2] b8 eb [2] 85 }

  condition:
    any of them
}