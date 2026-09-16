rule TTP_XOR_MULT_DOSStub_85e8 {
  strings:
    $key_85e8 = { d1 80 [2] a5 98 [2] e2 9a [2] a5 8b [2] eb 87 [2] e7 8d [2] f0 86 [2] eb c8 [2] d6 }

  condition:
    any of them
}