rule TTP_XOR_MULT_DOSStub_8350 {
  strings:
    $key_8350 = { d7 38 [2] a3 20 [2] e4 22 [2] a3 33 [2] ed 3f [2] e1 35 [2] f6 3e [2] ed 70 [2] d0 }

  condition:
    any of them
}