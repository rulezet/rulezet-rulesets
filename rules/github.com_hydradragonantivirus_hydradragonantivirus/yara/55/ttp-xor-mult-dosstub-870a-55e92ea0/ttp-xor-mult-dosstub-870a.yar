rule TTP_XOR_MULT_DOSStub_870a {
  strings:
    $key_870a = { d3 62 [2] a7 7a [2] e0 78 [2] a7 69 [2] e9 65 [2] e5 6f [2] f2 64 [2] e9 2a [2] d4 }

  condition:
    any of them
}