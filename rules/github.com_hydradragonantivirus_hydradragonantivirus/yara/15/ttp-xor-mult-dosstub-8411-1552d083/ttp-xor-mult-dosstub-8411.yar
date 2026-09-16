rule TTP_XOR_MULT_DOSStub_8411 {
  strings:
    $key_8411 = { d0 79 [2] a4 61 [2] e3 63 [2] a4 72 [2] ea 7e [2] e6 74 [2] f1 7f [2] ea 31 [2] d7 }

  condition:
    any of them
}