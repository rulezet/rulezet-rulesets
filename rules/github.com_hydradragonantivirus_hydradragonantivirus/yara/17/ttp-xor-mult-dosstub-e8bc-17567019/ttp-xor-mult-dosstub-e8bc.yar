rule TTP_XOR_MULT_DOSStub_e8bc {
  strings:
    $key_e8bc = { bc d4 [2] c8 cc [2] 8f ce [2] c8 df [2] 86 d3 [2] 8a d9 [2] 9d d2 [2] 86 9c [2] bb }

  condition:
    any of them
}