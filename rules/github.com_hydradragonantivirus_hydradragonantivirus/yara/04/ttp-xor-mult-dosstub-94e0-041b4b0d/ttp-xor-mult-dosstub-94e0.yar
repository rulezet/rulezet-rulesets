rule TTP_XOR_MULT_DOSStub_94e0 {
  strings:
    $key_94e0 = { c0 88 [2] b4 90 [2] f3 92 [2] b4 83 [2] fa 8f [2] f6 85 [2] e1 8e [2] fa c0 [2] c7 }

  condition:
    any of them
}