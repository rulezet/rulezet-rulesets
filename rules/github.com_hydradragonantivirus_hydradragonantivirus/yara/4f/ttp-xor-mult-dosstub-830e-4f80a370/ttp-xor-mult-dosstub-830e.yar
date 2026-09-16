rule TTP_XOR_MULT_DOSStub_830e {
  strings:
    $key_830e = { d7 66 [2] a3 7e [2] e4 7c [2] a3 6d [2] ed 61 [2] e1 6b [2] f6 60 [2] ed 2e [2] d0 }

  condition:
    any of them
}