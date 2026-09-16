rule TTP_XOR_MULT_DOSStub_d450 {
  strings:
    $key_d450 = { 80 38 [2] f4 20 [2] b3 22 [2] f4 33 [2] ba 3f [2] b6 35 [2] a1 3e [2] ba 70 [2] 87 }

  condition:
    any of them
}