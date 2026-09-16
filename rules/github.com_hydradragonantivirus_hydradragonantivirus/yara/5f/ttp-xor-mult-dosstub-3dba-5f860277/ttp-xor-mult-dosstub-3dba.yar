rule TTP_XOR_MULT_DOSStub_3dba {
  strings:
    $key_3dba = { 69 d2 [2] 1d ca [2] 5a c8 [2] 1d d9 [2] 53 d5 [2] 5f df [2] 48 d4 [2] 53 9a [2] 6e }

  condition:
    any of them
}