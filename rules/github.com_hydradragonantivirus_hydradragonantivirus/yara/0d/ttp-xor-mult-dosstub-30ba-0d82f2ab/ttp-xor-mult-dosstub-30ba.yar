rule TTP_XOR_MULT_DOSStub_30ba {
  strings:
    $key_30ba = { 64 d2 [2] 10 ca [2] 57 c8 [2] 10 d9 [2] 5e d5 [2] 52 df [2] 45 d4 [2] 5e 9a [2] 63 }

  condition:
    any of them
}