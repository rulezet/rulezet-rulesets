rule TTP_XOR_MULT_DOSStub_d7f5 {
  strings:
    $key_d7f5 = { 83 9d [2] f7 85 [2] b0 87 [2] f7 96 [2] b9 9a [2] b5 90 [2] a2 9b [2] b9 d5 [2] 84 }

  condition:
    any of them
}