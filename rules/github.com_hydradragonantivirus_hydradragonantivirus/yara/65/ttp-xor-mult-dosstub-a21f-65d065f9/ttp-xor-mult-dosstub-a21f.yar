rule TTP_XOR_MULT_DOSStub_a21f {
  strings:
    $key_a21f = { f6 77 [2] 82 6f [2] c5 6d [2] 82 7c [2] cc 70 [2] c0 7a [2] d7 71 [2] cc 3f [2] f1 }

  condition:
    any of them
}