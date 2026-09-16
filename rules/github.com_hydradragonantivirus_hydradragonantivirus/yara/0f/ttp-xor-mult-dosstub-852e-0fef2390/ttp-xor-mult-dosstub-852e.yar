rule TTP_XOR_MULT_DOSStub_852e {
  strings:
    $key_852e = { d1 46 [2] a5 5e [2] e2 5c [2] a5 4d [2] eb 41 [2] e7 4b [2] f0 40 [2] eb 0e [2] d6 }

  condition:
    any of them
}