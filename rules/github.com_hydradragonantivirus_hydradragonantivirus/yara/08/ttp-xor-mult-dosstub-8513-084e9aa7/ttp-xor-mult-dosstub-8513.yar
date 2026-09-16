rule TTP_XOR_MULT_DOSStub_8513 {
  strings:
    $key_8513 = { d1 7b [2] a5 63 [2] e2 61 [2] a5 70 [2] eb 7c [2] e7 76 [2] f0 7d [2] eb 33 [2] d6 }

  condition:
    any of them
}