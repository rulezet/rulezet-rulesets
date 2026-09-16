rule TTP_XOR_MULT_DOSStub_19bb {
  strings:
    $key_19bb = { 4d d3 [2] 39 cb [2] 7e c9 [2] 39 d8 [2] 77 d4 [2] 7b de [2] 6c d5 [2] 77 9b [2] 4a }

  condition:
    any of them
}