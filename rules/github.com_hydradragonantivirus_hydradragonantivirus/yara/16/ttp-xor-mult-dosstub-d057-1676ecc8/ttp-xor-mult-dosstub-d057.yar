rule TTP_XOR_MULT_DOSStub_d057 {
  strings:
    $key_d057 = { 84 3f [2] f0 27 [2] b7 25 [2] f0 34 [2] be 38 [2] b2 32 [2] a5 39 [2] be 77 [2] 83 }

  condition:
    any of them
}