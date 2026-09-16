rule TTP_XOR_MULT_DOSStub_8469 {
  strings:
    $key_8469 = { d0 01 [2] a4 19 [2] e3 1b [2] a4 0a [2] ea 06 [2] e6 0c [2] f1 07 [2] ea 49 [2] d7 }

  condition:
    any of them
}