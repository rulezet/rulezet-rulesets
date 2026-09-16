rule TTP_XOR_MULT_DOSStub_8439 {
  strings:
    $key_8439 = { d0 51 [2] a4 49 [2] e3 4b [2] a4 5a [2] ea 56 [2] e6 5c [2] f1 57 [2] ea 19 [2] d7 }

  condition:
    any of them
}