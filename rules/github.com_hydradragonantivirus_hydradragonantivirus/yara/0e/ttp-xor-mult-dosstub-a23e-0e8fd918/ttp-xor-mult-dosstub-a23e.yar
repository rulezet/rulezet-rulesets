rule TTP_XOR_MULT_DOSStub_a23e {
  strings:
    $key_a23e = { f6 56 [2] 82 4e [2] c5 4c [2] 82 5d [2] cc 51 [2] c0 5b [2] d7 50 [2] cc 1e [2] f1 }

  condition:
    any of them
}