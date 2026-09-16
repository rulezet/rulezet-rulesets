rule TTP_XOR_MULT_DOSStub_8421 {
  strings:
    $key_8421 = { d0 49 [2] a4 51 [2] e3 53 [2] a4 42 [2] ea 4e [2] e6 44 [2] f1 4f [2] ea 01 [2] d7 }

  condition:
    any of them
}