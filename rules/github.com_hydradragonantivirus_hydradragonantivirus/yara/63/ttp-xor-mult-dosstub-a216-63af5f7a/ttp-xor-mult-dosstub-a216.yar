rule TTP_XOR_MULT_DOSStub_a216 {
  strings:
    $key_a216 = { f6 7e [2] 82 66 [2] c5 64 [2] 82 75 [2] cc 79 [2] c0 73 [2] d7 78 [2] cc 36 [2] f1 }

  condition:
    any of them
}