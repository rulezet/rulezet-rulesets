rule TTP_XOR_MULT_DOSStub_77ba {
  strings:
    $key_77ba = { 23 d2 [2] 57 ca [2] 10 c8 [2] 57 d9 [2] 19 d5 [2] 15 df [2] 02 d4 [2] 19 9a [2] 24 }

  condition:
    any of them
}