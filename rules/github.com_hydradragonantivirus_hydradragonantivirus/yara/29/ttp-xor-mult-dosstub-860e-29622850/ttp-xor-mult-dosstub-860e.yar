rule TTP_XOR_MULT_DOSStub_860e {
  strings:
    $key_860e = { d2 66 [2] a6 7e [2] e1 7c [2] a6 6d [2] e8 61 [2] e4 6b [2] f3 60 [2] e8 2e [2] d5 }

  condition:
    any of them
}