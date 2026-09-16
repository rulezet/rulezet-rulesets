rule TTP_XOR_MULT_DOSStub_8426 {
  strings:
    $key_8426 = { d0 4e [2] a4 56 [2] e3 54 [2] a4 45 [2] ea 49 [2] e6 43 [2] f1 48 [2] ea 06 [2] d7 }

  condition:
    any of them
}