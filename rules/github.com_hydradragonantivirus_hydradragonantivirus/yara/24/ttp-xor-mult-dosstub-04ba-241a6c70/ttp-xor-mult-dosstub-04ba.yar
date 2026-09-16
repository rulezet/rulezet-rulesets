rule TTP_XOR_MULT_DOSStub_04ba {
  strings:
    $key_04ba = { 50 d2 [2] 24 ca [2] 63 c8 [2] 24 d9 [2] 6a d5 [2] 66 df [2] 71 d4 [2] 6a 9a [2] 57 }

  condition:
    any of them
}