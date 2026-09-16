rule TTP_XOR_MULT_DOSStub_6761 {
  strings:
    $key_6761 = { 33 09 [2] 47 11 [2] 00 13 [2] 47 02 [2] 09 0e [2] 05 04 [2] 12 0f [2] 09 41 [2] 34 }

  condition:
    any of them
}