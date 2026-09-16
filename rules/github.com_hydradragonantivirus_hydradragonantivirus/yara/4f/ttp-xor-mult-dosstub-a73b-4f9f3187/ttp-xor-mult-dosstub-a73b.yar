rule TTP_XOR_MULT_DOSStub_a73b {
  strings:
    $key_a73b = { f3 53 [2] 87 4b [2] c0 49 [2] 87 58 [2] c9 54 [2] c5 5e [2] d2 55 [2] c9 1b [2] f4 }

  condition:
    any of them
}