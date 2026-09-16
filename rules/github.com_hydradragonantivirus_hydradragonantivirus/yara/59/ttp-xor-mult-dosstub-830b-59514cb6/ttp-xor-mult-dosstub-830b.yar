rule TTP_XOR_MULT_DOSStub_830b {
  strings:
    $key_830b = { d7 63 [2] a3 7b [2] e4 79 [2] a3 68 [2] ed 64 [2] e1 6e [2] f6 65 [2] ed 2b [2] d0 }

  condition:
    any of them
}