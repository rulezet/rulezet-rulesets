rule TTP_XOR_MULT_DOSStub_d106 {
  strings:
    $key_d106 = { 85 6e [2] f1 76 [2] b6 74 [2] f1 65 [2] bf 69 [2] b3 63 [2] a4 68 [2] bf 26 [2] 82 }

  condition:
    any of them
}