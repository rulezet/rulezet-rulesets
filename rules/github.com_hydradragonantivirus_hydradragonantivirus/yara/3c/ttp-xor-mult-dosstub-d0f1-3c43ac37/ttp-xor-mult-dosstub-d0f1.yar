rule TTP_XOR_MULT_DOSStub_d0f1 {
  strings:
    $key_d0f1 = { 84 99 [2] f0 81 [2] b7 83 [2] f0 92 [2] be 9e [2] b2 94 [2] a5 9f [2] be d1 [2] 83 }

  condition:
    any of them
}