rule TTP_XOR_MULT_DOSStub_a284 {
  strings:
    $key_a284 = { f6 ec [2] 82 f4 [2] c5 f6 [2] 82 e7 [2] cc eb [2] c0 e1 [2] d7 ea [2] cc a4 [2] f1 }

  condition:
    any of them
}