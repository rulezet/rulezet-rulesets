rule TTP_XOR_MULT_DOSStub_d076 {
  strings:
    $key_d076 = { 84 1e [2] f0 06 [2] b7 04 [2] f0 15 [2] be 19 [2] b2 13 [2] a5 18 [2] be 56 [2] 83 }

  condition:
    any of them
}