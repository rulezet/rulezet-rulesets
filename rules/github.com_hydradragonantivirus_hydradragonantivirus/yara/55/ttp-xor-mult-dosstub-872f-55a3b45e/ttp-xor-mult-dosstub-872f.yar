rule TTP_XOR_MULT_DOSStub_872f {
  strings:
    $key_872f = { d3 47 [2] a7 5f [2] e0 5d [2] a7 4c [2] e9 40 [2] e5 4a [2] f2 41 [2] e9 0f [2] d4 }

  condition:
    any of them
}