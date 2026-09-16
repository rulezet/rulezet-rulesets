rule TTP_XOR_MULT_DOSStub_873d {
  strings:
    $key_873d = { d3 55 [2] a7 4d [2] e0 4f [2] a7 5e [2] e9 52 [2] e5 58 [2] f2 53 [2] e9 1d [2] d4 }

  condition:
    any of them
}