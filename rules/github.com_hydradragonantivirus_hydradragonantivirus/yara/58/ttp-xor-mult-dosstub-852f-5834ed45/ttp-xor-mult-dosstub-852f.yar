rule TTP_XOR_MULT_DOSStub_852f {
  strings:
    $key_852f = { d1 47 [2] a5 5f [2] e2 5d [2] a5 4c [2] eb 40 [2] e7 4a [2] f0 41 [2] eb 0f [2] d6 }

  condition:
    any of them
}