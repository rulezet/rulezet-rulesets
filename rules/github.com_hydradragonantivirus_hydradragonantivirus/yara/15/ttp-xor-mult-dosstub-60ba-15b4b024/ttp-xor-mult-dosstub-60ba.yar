rule TTP_XOR_MULT_DOSStub_60ba {
  strings:
    $key_60ba = { 34 d2 [2] 40 ca [2] 07 c8 [2] 40 d9 [2] 0e d5 [2] 02 df [2] 15 d4 [2] 0e 9a [2] 33 }

  condition:
    any of them
}