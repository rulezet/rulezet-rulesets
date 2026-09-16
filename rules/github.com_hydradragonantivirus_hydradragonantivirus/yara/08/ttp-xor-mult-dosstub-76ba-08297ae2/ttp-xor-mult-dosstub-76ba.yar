rule TTP_XOR_MULT_DOSStub_76ba {
  strings:
    $key_76ba = { 22 d2 [2] 56 ca [2] 11 c8 [2] 56 d9 [2] 18 d5 [2] 14 df [2] 03 d4 [2] 18 9a [2] 25 }

  condition:
    any of them
}