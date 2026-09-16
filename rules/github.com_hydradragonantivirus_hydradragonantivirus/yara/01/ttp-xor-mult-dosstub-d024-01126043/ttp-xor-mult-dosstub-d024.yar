rule TTP_XOR_MULT_DOSStub_d024 {
  strings:
    $key_d024 = { 84 4c [2] f0 54 [2] b7 56 [2] f0 47 [2] be 4b [2] b2 41 [2] a5 4a [2] be 04 [2] 83 }

  condition:
    any of them
}