rule TTP_XOR_MULT_DOSStub_6fbc {
  strings:
    $key_6fbc = { 3b d4 [2] 4f cc [2] 08 ce [2] 4f df [2] 01 d3 [2] 0d d9 [2] 1a d2 [2] 01 9c [2] 3c }

  condition:
    any of them
}