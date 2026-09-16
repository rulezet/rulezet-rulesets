rule TTP_XOR_MULT_DOSStub_a220 {
  strings:
    $key_a220 = { f6 48 [2] 82 50 [2] c5 52 [2] 82 43 [2] cc 4f [2] c0 45 [2] d7 4e [2] cc 00 [2] f1 }

  condition:
    any of them
}