rule TTP_XOR_MULT_DOSStub_857c {
  strings:
    $key_857c = { d1 14 [2] a5 0c [2] e2 0e [2] a5 1f [2] eb 13 [2] e7 19 [2] f0 12 [2] eb 5c [2] d6 }

  condition:
    any of them
}