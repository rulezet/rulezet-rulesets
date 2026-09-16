rule TTP_XOR_MULT_DOSStub_fdbc {
  strings:
    $key_fdbc = { a9 d4 [2] dd cc [2] 9a ce [2] dd df [2] 93 d3 [2] 9f d9 [2] 88 d2 [2] 93 9c [2] ae }

  condition:
    any of them
}