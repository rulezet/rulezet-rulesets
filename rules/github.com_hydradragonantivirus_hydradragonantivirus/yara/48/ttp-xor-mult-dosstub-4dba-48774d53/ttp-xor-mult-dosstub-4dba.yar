rule TTP_XOR_MULT_DOSStub_4dba {
  strings:
    $key_4dba = { 19 d2 [2] 6d ca [2] 2a c8 [2] 6d d9 [2] 23 d5 [2] 2f df [2] 38 d4 [2] 23 9a [2] 1e }

  condition:
    any of them
}