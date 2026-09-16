rule TTP_XOR_MULT_DOSStub_a25c {
  strings:
    $key_a25c = { f6 34 [2] 82 2c [2] c5 2e [2] 82 3f [2] cc 33 [2] c0 39 [2] d7 32 [2] cc 7c [2] f1 }

  condition:
    any of them
}