rule TTP_XOR_MULT_DOSStub_d0f3 {
  strings:
    $key_d0f3 = { 84 9b [2] f0 83 [2] b7 81 [2] f0 90 [2] be 9c [2] b2 96 [2] a5 9d [2] be d3 [2] 83 }

  condition:
    any of them
}