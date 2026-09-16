rule TTP_XOR_MULT_DOSStub_870d {
  strings:
    $key_870d = { d3 65 [2] a7 7d [2] e0 7f [2] a7 6e [2] e9 62 [2] e5 68 [2] f2 63 [2] e9 2d [2] d4 }

  condition:
    any of them
}