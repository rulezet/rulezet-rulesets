rule TTP_XOR_MULT_DOSStub_a201 {
  strings:
    $key_a201 = { f6 69 [2] 82 71 [2] c5 73 [2] 82 62 [2] cc 6e [2] c0 64 [2] d7 6f [2] cc 21 [2] f1 }

  condition:
    any of them
}