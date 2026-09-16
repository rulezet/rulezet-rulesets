rule TTP_XOR_MULT_DOSStub_8316 {
  strings:
    $key_8316 = { d7 7e [2] a3 66 [2] e4 64 [2] a3 75 [2] ed 79 [2] e1 73 [2] f6 78 [2] ed 36 [2] d0 }

  condition:
    any of them
}