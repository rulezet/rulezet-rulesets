rule TTP_XOR_MULT_DOSStub_d0e3 {
  strings:
    $key_d0e3 = { 84 8b [2] f0 93 [2] b7 91 [2] f0 80 [2] be 8c [2] b2 86 [2] a5 8d [2] be c3 [2] 83 }

  condition:
    any of them
}