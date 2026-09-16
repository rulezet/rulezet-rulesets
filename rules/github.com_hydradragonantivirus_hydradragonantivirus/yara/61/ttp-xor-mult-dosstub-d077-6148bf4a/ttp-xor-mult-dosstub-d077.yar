rule TTP_XOR_MULT_DOSStub_d077 {
  strings:
    $key_d077 = { 84 1f [2] f0 07 [2] b7 05 [2] f0 14 [2] be 18 [2] b2 12 [2] a5 19 [2] be 57 [2] 83 }

  condition:
    any of them
}