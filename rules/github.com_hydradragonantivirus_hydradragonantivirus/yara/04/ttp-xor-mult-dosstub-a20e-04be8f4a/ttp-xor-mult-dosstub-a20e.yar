rule TTP_XOR_MULT_DOSStub_a20e {
  strings:
    $key_a20e = { f6 66 [2] 82 7e [2] c5 7c [2] 82 6d [2] cc 61 [2] c0 6b [2] d7 60 [2] cc 2e [2] f1 }

  condition:
    any of them
}