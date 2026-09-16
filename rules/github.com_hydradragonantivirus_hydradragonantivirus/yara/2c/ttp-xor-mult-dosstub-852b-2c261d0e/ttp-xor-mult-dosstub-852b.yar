rule TTP_XOR_MULT_DOSStub_852b {
  strings:
    $key_852b = { d1 43 [2] a5 5b [2] e2 59 [2] a5 48 [2] eb 44 [2] e7 4e [2] f0 45 [2] eb 0b [2] d6 }

  condition:
    any of them
}