rule TTP_XOR_MULT_DOSStub_a207 {
  strings:
    $key_a207 = { f6 6f [2] 82 77 [2] c5 75 [2] 82 64 [2] cc 68 [2] c0 62 [2] d7 69 [2] cc 27 [2] f1 }

  condition:
    any of them
}