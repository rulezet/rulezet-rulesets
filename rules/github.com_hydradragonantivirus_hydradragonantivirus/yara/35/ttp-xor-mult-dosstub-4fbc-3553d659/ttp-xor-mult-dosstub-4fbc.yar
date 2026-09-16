rule TTP_XOR_MULT_DOSStub_4fbc {
  strings:
    $key_4fbc = { 1b d4 [2] 6f cc [2] 28 ce [2] 6f df [2] 21 d3 [2] 2d d9 [2] 3a d2 [2] 21 9c [2] 1c }

  condition:
    any of them
}