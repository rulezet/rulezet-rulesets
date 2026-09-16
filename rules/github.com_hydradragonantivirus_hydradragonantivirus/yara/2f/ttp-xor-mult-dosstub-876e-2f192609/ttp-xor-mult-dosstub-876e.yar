rule TTP_XOR_MULT_DOSStub_876e {
  strings:
    $key_876e = { d3 06 [2] a7 1e [2] e0 1c [2] a7 0d [2] e9 01 [2] e5 0b [2] f2 00 [2] e9 4e [2] d4 }

  condition:
    any of them
}