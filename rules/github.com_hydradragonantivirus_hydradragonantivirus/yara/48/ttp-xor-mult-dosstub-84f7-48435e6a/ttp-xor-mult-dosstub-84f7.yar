rule TTP_XOR_MULT_DOSStub_84f7 {
  strings:
    $key_84f7 = { d0 9f [2] a4 87 [2] e3 85 [2] a4 94 [2] ea 98 [2] e6 92 [2] f1 99 [2] ea d7 [2] d7 }

  condition:
    any of them
}