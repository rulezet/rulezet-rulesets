rule TTP_XOR_MULT_DOSStub_d750 {
  strings:
    $key_d750 = { 83 38 [2] f7 20 [2] b0 22 [2] f7 33 [2] b9 3f [2] b5 35 [2] a2 3e [2] b9 70 [2] 84 }

  condition:
    any of them
}