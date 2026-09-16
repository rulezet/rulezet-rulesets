rule TTP_XOR_MULT_DOSStub_debb {
  strings:
    $key_debb = { 8a d3 [2] fe cb [2] b9 c9 [2] fe d8 [2] b0 d4 [2] bc de [2] ab d5 [2] b0 9b [2] 8d }

  condition:
    any of them
}