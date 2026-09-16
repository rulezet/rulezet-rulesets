rule TTP_XOR_MULT_DOSStub_871e {
  strings:
    $key_871e = { d3 76 [2] a7 6e [2] e0 6c [2] a7 7d [2] e9 71 [2] e5 7b [2] f2 70 [2] e9 3e [2] d4 }

  condition:
    any of them
}