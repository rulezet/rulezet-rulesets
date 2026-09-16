rule TTP_XOR_MULT_DOSStub_a2e3 {
  strings:
    $key_a2e3 = { f6 8b [2] 82 93 [2] c5 91 [2] 82 80 [2] cc 8c [2] c0 86 [2] d7 8d [2] cc c3 [2] f1 }

  condition:
    any of them
}