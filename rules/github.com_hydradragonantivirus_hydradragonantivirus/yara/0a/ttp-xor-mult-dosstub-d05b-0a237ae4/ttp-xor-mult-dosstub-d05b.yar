rule TTP_XOR_MULT_DOSStub_d05b {
  strings:
    $key_d05b = { 84 33 [2] f0 2b [2] b7 29 [2] f0 38 [2] be 34 [2] b2 3e [2] a5 35 [2] be 7b [2] 83 }

  condition:
    any of them
}