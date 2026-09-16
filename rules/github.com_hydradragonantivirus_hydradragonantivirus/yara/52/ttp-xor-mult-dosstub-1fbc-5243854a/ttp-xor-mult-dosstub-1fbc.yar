rule TTP_XOR_MULT_DOSStub_1fbc {
  strings:
    $key_1fbc = { 4b d4 [2] 3f cc [2] 78 ce [2] 3f df [2] 71 d3 [2] 7d d9 [2] 6a d2 [2] 71 9c [2] 4c }

  condition:
    any of them
}