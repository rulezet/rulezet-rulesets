rule TTP_XOR_MULT_DOSStub_d7a8 {
  strings:
    $key_d7a8 = { 83 c0 [2] f7 d8 [2] b0 da [2] f7 cb [2] b9 c7 [2] b5 cd [2] a2 c6 [2] b9 88 [2] 84 }

  condition:
    any of them
}