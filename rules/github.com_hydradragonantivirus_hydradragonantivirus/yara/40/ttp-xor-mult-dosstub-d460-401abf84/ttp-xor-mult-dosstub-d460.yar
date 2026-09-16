rule TTP_XOR_MULT_DOSStub_d460 {
  strings:
    $key_d460 = { 80 08 [2] f4 10 [2] b3 12 [2] f4 03 [2] ba 0f [2] b6 05 [2] a1 0e [2] ba 40 [2] 87 }

  condition:
    any of them
}