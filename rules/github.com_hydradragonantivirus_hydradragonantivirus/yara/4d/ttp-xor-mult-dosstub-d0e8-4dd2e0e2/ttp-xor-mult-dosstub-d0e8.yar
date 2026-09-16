rule TTP_XOR_MULT_DOSStub_d0e8 {
  strings:
    $key_d0e8 = { 84 80 [2] f0 98 [2] b7 9a [2] f0 8b [2] be 87 [2] b2 8d [2] a5 86 [2] be c8 [2] 83 }

  condition:
    any of them
}