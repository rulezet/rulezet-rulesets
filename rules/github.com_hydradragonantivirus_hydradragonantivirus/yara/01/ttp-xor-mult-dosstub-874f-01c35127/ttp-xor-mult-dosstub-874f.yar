rule TTP_XOR_MULT_DOSStub_874f {
  strings:
    $key_874f = { d3 27 [2] a7 3f [2] e0 3d [2] a7 2c [2] e9 20 [2] e5 2a [2] f2 21 [2] e9 6f [2] d4 }

  condition:
    any of them
}