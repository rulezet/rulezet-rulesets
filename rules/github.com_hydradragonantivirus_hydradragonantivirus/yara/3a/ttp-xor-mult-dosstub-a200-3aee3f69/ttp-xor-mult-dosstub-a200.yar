rule TTP_XOR_MULT_DOSStub_a200 {
  strings:
    $key_a200 = { f6 68 [2] 82 70 [2] c5 72 [2] 82 63 [2] cc 6f [2] c0 65 [2] d7 6e [2] cc 20 [2] f1 }

  condition:
    any of them
}