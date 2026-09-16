rule TTP_XOR_MULT_DOSStub_8430 {
  strings:
    $key_8430 = { d0 58 [2] a4 40 [2] e3 42 [2] a4 53 [2] ea 5f [2] e6 55 [2] f1 5e [2] ea 10 [2] d7 }

  condition:
    any of them
}