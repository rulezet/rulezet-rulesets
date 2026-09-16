rule TTP_XOR_MULT_DOSStub_a26d {
  strings:
    $key_a26d = { f6 05 [2] 82 1d [2] c5 1f [2] 82 0e [2] cc 02 [2] c0 08 [2] d7 03 [2] cc 4d [2] f1 }

  condition:
    any of them
}