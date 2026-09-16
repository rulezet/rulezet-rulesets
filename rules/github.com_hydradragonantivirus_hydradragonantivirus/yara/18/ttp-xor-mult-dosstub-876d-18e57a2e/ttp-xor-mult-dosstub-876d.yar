rule TTP_XOR_MULT_DOSStub_876d {
  strings:
    $key_876d = { d3 05 [2] a7 1d [2] e0 1f [2] a7 0e [2] e9 02 [2] e5 08 [2] f2 03 [2] e9 4d [2] d4 }

  condition:
    any of them
}