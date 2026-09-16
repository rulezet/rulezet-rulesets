rule TTP_XOR_MULT_DOSStub_851a {
  strings:
    $key_851a = { d1 72 [2] a5 6a [2] e2 68 [2] a5 79 [2] eb 75 [2] e7 7f [2] f0 74 [2] eb 3a [2] d6 }

  condition:
    any of them
}