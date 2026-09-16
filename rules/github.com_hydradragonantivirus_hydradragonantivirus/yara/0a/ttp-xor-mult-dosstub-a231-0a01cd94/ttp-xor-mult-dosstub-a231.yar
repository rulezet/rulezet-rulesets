rule TTP_XOR_MULT_DOSStub_a231 {
  strings:
    $key_a231 = { f6 59 [2] 82 41 [2] c5 43 [2] 82 52 [2] cc 5e [2] c0 54 [2] d7 5f [2] cc 11 [2] f1 }

  condition:
    any of them
}