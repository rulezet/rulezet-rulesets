rule TTP_XOR_MULT_DOSStub_853e {
  strings:
    $key_853e = { d1 56 [2] a5 4e [2] e2 4c [2] a5 5d [2] eb 51 [2] e7 5b [2] f0 50 [2] eb 1e [2] d6 }

  condition:
    any of them
}