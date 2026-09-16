rule TTP_XOR_MULT_DOSStub_d4d2 {
  strings:
    $key_d4d2 = { 80 ba [2] f4 a2 [2] b3 a0 [2] f4 b1 [2] ba bd [2] b6 b7 [2] a1 bc [2] ba f2 [2] 87 }

  condition:
    any of them
}