rule TTP_XOR_MULT_DOSStub_58bc {
  strings:
    $key_58bc = { 0c d4 [2] 78 cc [2] 3f ce [2] 78 df [2] 36 d3 [2] 3a d9 [2] 2d d2 [2] 36 9c [2] 0b }

  condition:
    any of them
}