rule TTP_XOR_MULT_DOSStub_d032 {
  strings:
    $key_d032 = { 84 5a [2] f0 42 [2] b7 40 [2] f0 51 [2] be 5d [2] b2 57 [2] a5 5c [2] be 12 [2] 83 }

  condition:
    any of them
}