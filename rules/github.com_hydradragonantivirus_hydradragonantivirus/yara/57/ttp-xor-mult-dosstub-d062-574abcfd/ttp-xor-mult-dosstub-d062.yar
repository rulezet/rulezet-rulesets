rule TTP_XOR_MULT_DOSStub_d062 {
  strings:
    $key_d062 = { 84 0a [2] f0 12 [2] b7 10 [2] f0 01 [2] be 0d [2] b2 07 [2] a5 0c [2] be 42 [2] 83 }

  condition:
    any of them
}