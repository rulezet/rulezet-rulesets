rule TTP_XOR_MULT_DOSStub_960b {
  strings:
    $key_960b = { c2 63 [2] b6 7b [2] f1 79 [2] b6 68 [2] f8 64 [2] f4 6e [2] e3 65 [2] f8 2b [2] c5 }

  condition:
    any of them
}