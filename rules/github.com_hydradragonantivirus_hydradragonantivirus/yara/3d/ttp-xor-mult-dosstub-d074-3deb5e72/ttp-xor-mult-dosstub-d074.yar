rule TTP_XOR_MULT_DOSStub_d074 {
  strings:
    $key_d074 = { 84 1c [2] f0 04 [2] b7 06 [2] f0 17 [2] be 1b [2] b2 11 [2] a5 1a [2] be 54 [2] 83 }

  condition:
    any of them
}