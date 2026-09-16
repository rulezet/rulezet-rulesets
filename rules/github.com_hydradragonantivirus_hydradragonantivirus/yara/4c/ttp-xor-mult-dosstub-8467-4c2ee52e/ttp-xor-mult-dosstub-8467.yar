rule TTP_XOR_MULT_DOSStub_8467 {
  strings:
    $key_8467 = { d0 0f [2] a4 17 [2] e3 15 [2] a4 04 [2] ea 08 [2] e6 02 [2] f1 09 [2] ea 47 [2] d7 }

  condition:
    any of them
}