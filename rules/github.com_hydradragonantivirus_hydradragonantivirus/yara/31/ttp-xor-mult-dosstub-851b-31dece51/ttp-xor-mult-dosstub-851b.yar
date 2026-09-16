rule TTP_XOR_MULT_DOSStub_851b {
  strings:
    $key_851b = { d1 73 [2] a5 6b [2] e2 69 [2] a5 78 [2] eb 74 [2] e7 7e [2] f0 75 [2] eb 3b [2] d6 }

  condition:
    any of them
}