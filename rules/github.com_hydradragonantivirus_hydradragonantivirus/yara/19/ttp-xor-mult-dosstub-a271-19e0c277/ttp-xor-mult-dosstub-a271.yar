rule TTP_XOR_MULT_DOSStub_a271 {
  strings:
    $key_a271 = { f6 19 [2] 82 01 [2] c5 03 [2] 82 12 [2] cc 1e [2] c0 14 [2] d7 1f [2] cc 51 [2] f1 }

  condition:
    any of them
}