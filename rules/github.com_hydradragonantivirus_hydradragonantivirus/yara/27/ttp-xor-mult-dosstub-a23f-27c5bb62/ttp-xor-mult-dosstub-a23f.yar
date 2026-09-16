rule TTP_XOR_MULT_DOSStub_a23f {
  strings:
    $key_a23f = { f6 57 [2] 82 4f [2] c5 4d [2] 82 5c [2] cc 50 [2] c0 5a [2] d7 51 [2] cc 1f [2] f1 }

  condition:
    any of them
}