rule TTP_XOR_MULT_DOSStub_75ba {
  strings:
    $key_75ba = { 21 d2 [2] 55 ca [2] 12 c8 [2] 55 d9 [2] 1b d5 [2] 17 df [2] 00 d4 [2] 1b 9a [2] 26 }

  condition:
    any of them
}