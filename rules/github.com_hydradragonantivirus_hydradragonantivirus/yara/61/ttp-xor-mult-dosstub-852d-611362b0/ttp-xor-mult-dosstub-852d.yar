rule TTP_XOR_MULT_DOSStub_852d {
  strings:
    $key_852d = { d1 45 [2] a5 5d [2] e2 5f [2] a5 4e [2] eb 42 [2] e7 48 [2] f0 43 [2] eb 0d [2] d6 }

  condition:
    any of them
}