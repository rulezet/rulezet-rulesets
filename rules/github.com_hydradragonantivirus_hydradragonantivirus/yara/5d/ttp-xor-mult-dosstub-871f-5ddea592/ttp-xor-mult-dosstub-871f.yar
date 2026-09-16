rule TTP_XOR_MULT_DOSStub_871f {
  strings:
    $key_871f = { d3 77 [2] a7 6f [2] e0 6d [2] a7 7c [2] e9 70 [2] e5 7a [2] f2 71 [2] e9 3f [2] d4 }

  condition:
    any of them
}