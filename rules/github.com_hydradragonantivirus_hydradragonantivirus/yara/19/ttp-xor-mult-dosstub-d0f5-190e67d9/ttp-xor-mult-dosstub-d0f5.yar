rule TTP_XOR_MULT_DOSStub_d0f5 {
  strings:
    $key_d0f5 = { 84 9d [2] f0 85 [2] b7 87 [2] f0 96 [2] be 9a [2] b2 90 [2] a5 9b [2] be d5 [2] 83 }

  condition:
    any of them
}