rule TTP_XOR_MULT_DOSStub_c9bb {
  strings:
    $key_c9bb = { 9d d3 [2] e9 cb [2] ae c9 [2] e9 d8 [2] a7 d4 [2] ab de [2] bc d5 [2] a7 9b [2] 9a }

  condition:
    any of them
}