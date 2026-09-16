rule TTP_XOR_MULT_DOSStub_8529 {
  strings:
    $key_8529 = { d1 41 [2] a5 59 [2] e2 5b [2] a5 4a [2] eb 46 [2] e7 4c [2] f0 47 [2] eb 09 [2] d6 }

  condition:
    any of them
}