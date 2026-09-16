rule TTP_XOR_MULT_DOSStub_5fbc {
  strings:
    $key_5fbc = { 0b d4 [2] 7f cc [2] 38 ce [2] 7f df [2] 31 d3 [2] 3d d9 [2] 2a d2 [2] 31 9c [2] 0c }

  condition:
    any of them
}