rule TTP_XOR_MULT_DOSStub_d759 {
  strings:
    $key_d759 = { 83 31 [2] f7 29 [2] b0 2b [2] f7 3a [2] b9 36 [2] b5 3c [2] a2 37 [2] b9 79 [2] 84 }

  condition:
    any of them
}