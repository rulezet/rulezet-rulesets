rule TTP_XOR_MULT_DOSStub_d126 {
  strings:
    $key_d126 = { 85 4e [2] f1 56 [2] b6 54 [2] f1 45 [2] bf 49 [2] b3 43 [2] a4 48 [2] bf 06 [2] 82 }

  condition:
    any of them
}