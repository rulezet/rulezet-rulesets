rule TTP_XOR_MULT_DOSStub_0dba {
  strings:
    $key_0dba = { 59 d2 [2] 2d ca [2] 6a c8 [2] 2d d9 [2] 63 d5 [2] 6f df [2] 78 d4 [2] 63 9a [2] 5e }

  condition:
    any of them
}