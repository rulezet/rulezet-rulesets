rule TTP_XOR_MULT_DOSStub_a21c {
  strings:
    $key_a21c = { f6 74 [2] 82 6c [2] c5 6e [2] 82 7f [2] cc 73 [2] c0 79 [2] d7 72 [2] cc 3c [2] f1 }

  condition:
    any of them
}