rule TTP_XOR_MULT_DOSStub_870e {
  strings:
    $key_870e = { d3 66 [2] a7 7e [2] e0 7c [2] a7 6d [2] e9 61 [2] e5 6b [2] f2 60 [2] e9 2e [2] d4 }

  condition:
    any of them
}