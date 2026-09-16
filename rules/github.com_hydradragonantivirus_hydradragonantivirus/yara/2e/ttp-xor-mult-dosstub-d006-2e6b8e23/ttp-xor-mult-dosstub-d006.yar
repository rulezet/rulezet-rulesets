rule TTP_XOR_MULT_DOSStub_d006 {
  strings:
    $key_d006 = { 84 6e [2] f0 76 [2] b7 74 [2] f0 65 [2] be 69 [2] b2 63 [2] a5 68 [2] be 26 [2] 83 }

  condition:
    any of them
}