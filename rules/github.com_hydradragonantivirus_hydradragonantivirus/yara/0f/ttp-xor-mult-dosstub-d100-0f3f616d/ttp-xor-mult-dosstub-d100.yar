rule TTP_XOR_MULT_DOSStub_d100 {
  strings:
    $key_d100 = { 85 68 [2] f1 70 [2] b6 72 [2] f1 63 [2] bf 6f [2] b3 65 [2] a4 6e [2] bf 20 [2] 82 }

  condition:
    any of them
}