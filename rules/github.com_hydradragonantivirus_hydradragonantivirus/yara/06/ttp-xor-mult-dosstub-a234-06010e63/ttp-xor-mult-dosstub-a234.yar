rule TTP_XOR_MULT_DOSStub_a234 {
  strings:
    $key_a234 = { f6 5c [2] 82 44 [2] c5 46 [2] 82 57 [2] cc 5b [2] c0 51 [2] d7 5a [2] cc 14 [2] f1 }

  condition:
    any of them
}