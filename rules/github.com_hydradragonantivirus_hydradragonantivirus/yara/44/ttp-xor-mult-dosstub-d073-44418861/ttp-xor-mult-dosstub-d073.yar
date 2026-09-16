rule TTP_XOR_MULT_DOSStub_d073 {
  strings:
    $key_d073 = { 84 1b [2] f0 03 [2] b7 01 [2] f0 10 [2] be 1c [2] b2 16 [2] a5 1d [2] be 53 [2] 83 }

  condition:
    any of them
}