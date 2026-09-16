rule TTP_XOR_MULT_DOSStub_3fbc {
  strings:
    $key_3fbc = { 6b d4 [2] 1f cc [2] 58 ce [2] 1f df [2] 51 d3 [2] 5d d9 [2] 4a d2 [2] 51 9c [2] 6c }

  condition:
    any of them
}