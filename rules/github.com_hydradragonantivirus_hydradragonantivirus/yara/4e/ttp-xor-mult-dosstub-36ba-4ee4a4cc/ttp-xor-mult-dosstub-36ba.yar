rule TTP_XOR_MULT_DOSStub_36ba {
  strings:
    $key_36ba = { 62 d2 [2] 16 ca [2] 51 c8 [2] 16 d9 [2] 58 d5 [2] 54 df [2] 43 d4 [2] 58 9a [2] 65 }

  condition:
    any of them
}