rule TTP_XOR_MULT_DOSStub_850e {
  strings:
    $key_850e = { d1 66 [2] a5 7e [2] e2 7c [2] a5 6d [2] eb 61 [2] e7 6b [2] f0 60 [2] eb 2e [2] d6 }

  condition:
    any of them
}