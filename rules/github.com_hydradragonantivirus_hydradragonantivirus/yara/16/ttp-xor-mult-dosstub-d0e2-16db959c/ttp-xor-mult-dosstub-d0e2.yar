rule TTP_XOR_MULT_DOSStub_d0e2 {
  strings:
    $key_d0e2 = { 84 8a [2] f0 92 [2] b7 90 [2] f0 81 [2] be 8d [2] b2 87 [2] a5 8c [2] be c2 [2] 83 }

  condition:
    any of them
}