rule TTP_XOR_MULT_DOSStub_d735 {
  strings:
    $key_d735 = { 83 5d [2] f7 45 [2] b0 47 [2] f7 56 [2] b9 5a [2] b5 50 [2] a2 5b [2] b9 15 [2] 84 }

  condition:
    any of them
}