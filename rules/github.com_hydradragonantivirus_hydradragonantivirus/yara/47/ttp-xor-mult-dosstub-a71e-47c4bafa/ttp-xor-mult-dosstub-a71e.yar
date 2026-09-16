rule TTP_XOR_MULT_DOSStub_a71e {
  strings:
    $key_a71e = { f3 76 [2] 87 6e [2] c0 6c [2] 87 7d [2] c9 71 [2] c5 7b [2] d2 70 [2] c9 3e [2] f4 }

  condition:
    any of them
}