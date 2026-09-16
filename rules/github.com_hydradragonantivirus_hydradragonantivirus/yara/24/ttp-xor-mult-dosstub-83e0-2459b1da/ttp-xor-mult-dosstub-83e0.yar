rule TTP_XOR_MULT_DOSStub_83e0 {
  strings:
    $key_83e0 = { d7 88 [2] a3 90 [2] e4 92 [2] a3 83 [2] ed 8f [2] e1 85 [2] f6 8e [2] ed c0 [2] d0 }

  condition:
    any of them
}