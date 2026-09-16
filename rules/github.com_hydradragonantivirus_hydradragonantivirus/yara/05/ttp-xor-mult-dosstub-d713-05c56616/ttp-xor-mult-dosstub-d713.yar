rule TTP_XOR_MULT_DOSStub_d713 {
  strings:
    $key_d713 = { 83 7b [2] f7 63 [2] b0 61 [2] f7 70 [2] b9 7c [2] b5 76 [2] a2 7d [2] b9 33 [2] 84 }

  condition:
    any of them
}