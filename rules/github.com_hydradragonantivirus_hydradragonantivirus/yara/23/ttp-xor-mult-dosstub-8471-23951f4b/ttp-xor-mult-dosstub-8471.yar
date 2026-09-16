rule TTP_XOR_MULT_DOSStub_8471 {
  strings:
    $key_8471 = { d0 19 [2] a4 01 [2] e3 03 [2] a4 12 [2] ea 1e [2] e6 14 [2] f1 1f [2] ea 51 [2] d7 }

  condition:
    any of them
}