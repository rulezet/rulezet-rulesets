rule TTP_XOR_MULT_DOSStub_a26b {
  strings:
    $key_a26b = { f6 03 [2] 82 1b [2] c5 19 [2] 82 08 [2] cc 04 [2] c0 0e [2] d7 05 [2] cc 4b [2] f1 }

  condition:
    any of them
}