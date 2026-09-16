rule TTP_XOR_MULT_DOSStub_43bb {
  strings:
    $key_43bb = { 17 d3 [2] 63 cb [2] 24 c9 [2] 63 d8 [2] 2d d4 [2] 21 de [2] 36 d5 [2] 2d 9b [2] 10 }

  condition:
    any of them
}