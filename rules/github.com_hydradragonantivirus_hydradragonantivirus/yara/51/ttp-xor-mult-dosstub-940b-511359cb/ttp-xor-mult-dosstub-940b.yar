rule TTP_XOR_MULT_DOSStub_940b {
  strings:
    $key_940b = { c0 63 [2] b4 7b [2] f3 79 [2] b4 68 [2] fa 64 [2] f6 6e [2] e1 65 [2] fa 2b [2] c7 }

  condition:
    any of them
}