rule TTP_XOR_MULT_DOSStub_d001 {
  strings:
    $key_d001 = { 84 69 [2] f0 71 [2] b7 73 [2] f0 62 [2] be 6e [2] b2 64 [2] a5 6f [2] be 21 [2] 83 }

  condition:
    any of them
}