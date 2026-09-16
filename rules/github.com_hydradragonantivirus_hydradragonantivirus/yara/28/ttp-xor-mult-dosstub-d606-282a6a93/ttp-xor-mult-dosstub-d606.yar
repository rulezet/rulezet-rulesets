rule TTP_XOR_MULT_DOSStub_d606 {
  strings:
    $key_d606 = { 82 6e [2] f6 76 [2] b1 74 [2] f6 65 [2] b8 69 [2] b4 63 [2] a3 68 [2] b8 26 [2] 85 }

  condition:
    any of them
}