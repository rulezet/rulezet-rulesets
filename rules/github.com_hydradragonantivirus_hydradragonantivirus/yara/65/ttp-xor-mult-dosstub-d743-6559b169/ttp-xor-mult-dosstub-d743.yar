rule TTP_XOR_MULT_DOSStub_d743 {
  strings:
    $key_d743 = { 83 2b [2] f7 33 [2] b0 31 [2] f7 20 [2] b9 2c [2] b5 26 [2] a2 2d [2] b9 63 [2] 84 }

  condition:
    any of them
}