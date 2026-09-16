rule TTP_XOR_MULT_DOSStub_8306 {
  strings:
    $key_8306 = { d7 6e [2] a3 76 [2] e4 74 [2] a3 65 [2] ed 69 [2] e1 63 [2] f6 68 [2] ed 26 [2] d0 }

  condition:
    any of them
}