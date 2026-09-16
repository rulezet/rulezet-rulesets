rule TTP_XOR_MULT_DOSStub_857f {
  strings:
    $key_857f = { d1 17 [2] a5 0f [2] e2 0d [2] a5 1c [2] eb 10 [2] e7 1a [2] f0 11 [2] eb 5f [2] d6 }

  condition:
    any of them
}