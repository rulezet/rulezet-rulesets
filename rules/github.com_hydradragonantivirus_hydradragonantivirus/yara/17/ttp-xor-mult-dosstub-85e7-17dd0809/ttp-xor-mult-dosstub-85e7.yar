rule TTP_XOR_MULT_DOSStub_85e7 {
  strings:
    $key_85e7 = { d1 8f [2] a5 97 [2] e2 95 [2] a5 84 [2] eb 88 [2] e7 82 [2] f0 89 [2] eb c7 [2] d6 }

  condition:
    any of them
}