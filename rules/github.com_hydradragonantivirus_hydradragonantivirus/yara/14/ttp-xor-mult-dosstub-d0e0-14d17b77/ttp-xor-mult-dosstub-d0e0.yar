rule TTP_XOR_MULT_DOSStub_d0e0 {
  strings:
    $key_d0e0 = { 84 88 [2] f0 90 [2] b7 92 [2] f0 83 [2] be 8f [2] b2 85 [2] a5 8e [2] be c0 [2] 83 }

  condition:
    any of them
}