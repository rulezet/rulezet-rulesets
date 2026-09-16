rule TTP_XOR_MULT_DOSStub_d715 {
  strings:
    $key_d715 = { 83 7d [2] f7 65 [2] b0 67 [2] f7 76 [2] b9 7a [2] b5 70 [2] a2 7b [2] b9 35 [2] 84 }

  condition:
    any of them
}