rule TTP_XOR_MULT_DOSStub_976d {
  strings:
    $key_976d = { c3 05 [2] b7 1d [2] f0 1f [2] b7 0e [2] f9 02 [2] f5 08 [2] e2 03 [2] f9 4d [2] c4 }

  condition:
    any of them
}