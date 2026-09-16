rule TTP_XOR_MULT_DOSStub_d736 {
  strings:
    $key_d736 = { 83 5e [2] f7 46 [2] b0 44 [2] f7 55 [2] b9 59 [2] b5 53 [2] a2 58 [2] b9 16 [2] 84 }

  condition:
    any of them
}