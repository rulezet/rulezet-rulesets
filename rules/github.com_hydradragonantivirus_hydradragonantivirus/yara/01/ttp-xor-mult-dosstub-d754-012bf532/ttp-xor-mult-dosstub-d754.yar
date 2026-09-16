rule TTP_XOR_MULT_DOSStub_d754 {
  strings:
    $key_d754 = { 83 3c [2] f7 24 [2] b0 26 [2] f7 37 [2] b9 3b [2] b5 31 [2] a2 3a [2] b9 74 [2] 84 }

  condition:
    any of them
}