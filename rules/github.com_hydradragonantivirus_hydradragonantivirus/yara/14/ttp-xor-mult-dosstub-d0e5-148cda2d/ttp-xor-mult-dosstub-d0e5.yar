rule TTP_XOR_MULT_DOSStub_d0e5 {
  strings:
    $key_d0e5 = { 84 8d [2] f0 95 [2] b7 97 [2] f0 86 [2] be 8a [2] b2 80 [2] a5 8b [2] be c5 [2] 83 }

  condition:
    any of them
}