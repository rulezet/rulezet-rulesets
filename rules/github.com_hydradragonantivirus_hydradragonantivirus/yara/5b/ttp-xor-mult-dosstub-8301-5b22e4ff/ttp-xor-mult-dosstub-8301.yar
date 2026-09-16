rule TTP_XOR_MULT_DOSStub_8301 {
  strings:
    $key_8301 = { d7 69 [2] a3 71 [2] e4 73 [2] a3 62 [2] ed 6e [2] e1 64 [2] f6 6f [2] ed 21 [2] d0 }

  condition:
    any of them
}