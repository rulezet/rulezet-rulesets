rule TTP_XOR_MULT_DOSStub_a229 {
  strings:
    $key_a229 = { f6 41 [2] 82 59 [2] c5 5b [2] 82 4a [2] cc 46 [2] c0 4c [2] d7 47 [2] cc 09 [2] f1 }

  condition:
    any of them
}