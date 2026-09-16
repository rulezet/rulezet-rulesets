rule TTP_XOR_MULT_DOSStub_d035 {
  strings:
    $key_d035 = { 84 5d [2] f0 45 [2] b7 47 [2] f0 56 [2] be 5a [2] b2 50 [2] a5 5b [2] be 15 [2] 83 }

  condition:
    any of them
}