rule TTP_XOR_MULT_DOSStub_875f {
  strings:
    $key_875f = { d3 37 [2] a7 2f [2] e0 2d [2] a7 3c [2] e9 30 [2] e5 3a [2] f2 31 [2] e9 7f [2] d4 }

  condition:
    any of them
}