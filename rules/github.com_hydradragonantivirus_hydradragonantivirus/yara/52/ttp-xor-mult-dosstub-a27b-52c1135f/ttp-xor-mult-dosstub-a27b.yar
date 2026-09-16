rule TTP_XOR_MULT_DOSStub_a27b {
  strings:
    $key_a27b = { f6 13 [2] 82 0b [2] c5 09 [2] 82 18 [2] cc 14 [2] c0 1e [2] d7 15 [2] cc 5b [2] f1 }

  condition:
    any of them
}