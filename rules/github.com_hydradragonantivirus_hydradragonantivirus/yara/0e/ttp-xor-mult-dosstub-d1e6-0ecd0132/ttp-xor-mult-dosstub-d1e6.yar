rule TTP_XOR_MULT_DOSStub_d1e6 {
  strings:
    $key_d1e6 = { 85 8e [2] f1 96 [2] b6 94 [2] f1 85 [2] bf 89 [2] b3 83 [2] a4 88 [2] bf c6 [2] 82 }

  condition:
    any of them
}