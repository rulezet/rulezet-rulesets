rule TTP_XOR_MULT_DOSStub_45ba {
  strings:
    $key_45ba = { 11 d2 [2] 65 ca [2] 22 c8 [2] 65 d9 [2] 2b d5 [2] 27 df [2] 30 d4 [2] 2b 9a [2] 16 }

  condition:
    any of them
}