rule TTP_XOR_MULT_DOSStub_d704 {
  strings:
    $key_d704 = { 83 6c [2] f7 74 [2] b0 76 [2] f7 67 [2] b9 6b [2] b5 61 [2] a2 6a [2] b9 24 [2] 84 }

  condition:
    any of them
}