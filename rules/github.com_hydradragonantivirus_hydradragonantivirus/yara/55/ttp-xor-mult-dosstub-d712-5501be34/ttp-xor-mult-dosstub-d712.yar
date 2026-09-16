rule TTP_XOR_MULT_DOSStub_d712 {
  strings:
    $key_d712 = { 83 7a [2] f7 62 [2] b0 60 [2] f7 71 [2] b9 7d [2] b5 77 [2] a2 7c [2] b9 32 [2] 84 }

  condition:
    any of them
}