rule TTP_XOR_MULT_DOSStub_840b {
  strings:
    $key_840b = { d0 63 [2] a4 7b [2] e3 79 [2] a4 68 [2] ea 64 [2] e6 6e [2] f1 65 [2] ea 2b [2] d7 }

  condition:
    any of them
}