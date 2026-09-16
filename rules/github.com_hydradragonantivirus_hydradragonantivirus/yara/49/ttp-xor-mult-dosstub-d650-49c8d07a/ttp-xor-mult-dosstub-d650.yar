rule TTP_XOR_MULT_DOSStub_d650 {
  strings:
    $key_d650 = { 82 38 [2] f6 20 [2] b1 22 [2] f6 33 [2] b8 3f [2] b4 35 [2] a3 3e [2] b8 70 [2] 85 }

  condition:
    any of them
}