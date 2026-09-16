rule TTP_XOR_MULT_DOSStub_d0e9 {
  strings:
    $key_d0e9 = { 84 81 [2] f0 99 [2] b7 9b [2] f0 8a [2] be 86 [2] b2 8c [2] a5 87 [2] be c9 [2] 83 }

  condition:
    any of them
}