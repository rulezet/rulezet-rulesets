rule TTP_XOR_MULT_DOSStub_d0b7 {
  strings:
    $key_d0b7 = { 84 df [2] f0 c7 [2] b7 c5 [2] f0 d4 [2] be d8 [2] b2 d2 [2] a5 d9 [2] be 97 [2] 83 }

  condition:
    any of them
}