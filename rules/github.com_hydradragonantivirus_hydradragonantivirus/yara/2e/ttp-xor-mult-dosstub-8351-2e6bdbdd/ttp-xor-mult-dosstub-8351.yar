rule TTP_XOR_MULT_DOSStub_8351 {
  strings:
    $key_8351 = { d7 39 [2] a3 21 [2] e4 23 [2] a3 32 [2] ed 3e [2] e1 34 [2] f6 3f [2] ed 71 [2] d0 }

  condition:
    any of them
}