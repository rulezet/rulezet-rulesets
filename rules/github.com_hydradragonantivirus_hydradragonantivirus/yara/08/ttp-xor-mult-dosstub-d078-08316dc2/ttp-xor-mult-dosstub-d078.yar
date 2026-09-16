rule TTP_XOR_MULT_DOSStub_d078 {
  strings:
    $key_d078 = { 84 10 [2] f0 08 [2] b7 0a [2] f0 1b [2] be 17 [2] b2 1d [2] a5 16 [2] be 58 [2] 83 }

  condition:
    any of them
}