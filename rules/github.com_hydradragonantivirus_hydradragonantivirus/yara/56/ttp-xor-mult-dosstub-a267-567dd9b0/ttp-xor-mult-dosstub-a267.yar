rule TTP_XOR_MULT_DOSStub_a267 {
  strings:
    $key_a267 = { f6 0f [2] 82 17 [2] c5 15 [2] 82 04 [2] cc 08 [2] c0 02 [2] d7 09 [2] cc 47 [2] f1 }

  condition:
    any of them
}