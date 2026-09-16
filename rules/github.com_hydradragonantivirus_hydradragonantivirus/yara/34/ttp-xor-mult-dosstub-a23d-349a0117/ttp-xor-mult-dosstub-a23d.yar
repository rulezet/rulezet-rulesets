rule TTP_XOR_MULT_DOSStub_a23d {
  strings:
    $key_a23d = { f6 55 [2] 82 4d [2] c5 4f [2] 82 5e [2] cc 52 [2] c0 58 [2] d7 53 [2] cc 1d [2] f1 }

  condition:
    any of them
}