rule TTP_XOR_MULT_DOSStub_857a {
  strings:
    $key_857a = { d1 12 [2] a5 0a [2] e2 08 [2] a5 19 [2] eb 15 [2] e7 1f [2] f0 14 [2] eb 5a [2] d6 }

  condition:
    any of them
}