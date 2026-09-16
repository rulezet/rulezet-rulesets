rule TTP_XOR_MULT_DOSStub_d406 {
  strings:
    $key_d406 = { 80 6e [2] f4 76 [2] b3 74 [2] f4 65 [2] ba 69 [2] b6 63 [2] a1 68 [2] ba 26 [2] 87 }

  condition:
    any of them
}