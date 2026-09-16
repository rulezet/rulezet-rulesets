rule TTP_XOR_MULT_DOSStub_8296 {
  strings:
    $key_8296 = { d6 fe [2] a2 e6 [2] e5 e4 [2] a2 f5 [2] ec f9 [2] e0 f3 [2] f7 f8 [2] ec b6 [2] d1 }

  condition:
    any of them
}