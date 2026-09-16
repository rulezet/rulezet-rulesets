rule TTP_XOR_MULT_DOSStub_746e {
  strings:
    $key_746e = { 20 06 [2] 54 1e [2] 13 1c [2] 54 0d [2] 1a 01 [2] 16 0b [2] 01 00 [2] 1a 4e [2] 27 }

  condition:
    any of them
}