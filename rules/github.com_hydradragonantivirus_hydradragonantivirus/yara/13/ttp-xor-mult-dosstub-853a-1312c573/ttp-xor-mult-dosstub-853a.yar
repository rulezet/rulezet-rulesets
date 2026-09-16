rule TTP_XOR_MULT_DOSStub_853a {
  strings:
    $key_853a = { d1 52 [2] a5 4a [2] e2 48 [2] a5 59 [2] eb 55 [2] e7 5f [2] f0 54 [2] eb 1a [2] d6 }

  condition:
    any of them
}