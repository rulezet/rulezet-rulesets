rule TTP_XOR_MULT_DOSStub_97e0 {
  strings:
    $key_97e0 = { c3 88 [2] b7 90 [2] f0 92 [2] b7 83 [2] f9 8f [2] f5 85 [2] e2 8e [2] f9 c0 [2] c4 }

  condition:
    any of them
}