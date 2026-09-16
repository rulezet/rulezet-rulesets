rule TTP_XOR_MULT_DOSStub_d739 {
  strings:
    $key_d739 = { 83 51 [2] f7 49 [2] b0 4b [2] f7 5a [2] b9 56 [2] b5 5c [2] a2 57 [2] b9 19 [2] 84 }

  condition:
    any of them
}