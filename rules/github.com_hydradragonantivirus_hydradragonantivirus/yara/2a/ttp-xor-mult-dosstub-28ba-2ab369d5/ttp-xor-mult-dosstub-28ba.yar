rule TTP_XOR_MULT_DOSStub_28ba {
  strings:
    $key_28ba = { 7c d2 [2] 08 ca [2] 4f c8 [2] 08 d9 [2] 46 d5 [2] 4a df [2] 5d d4 [2] 46 9a [2] 7b }

  condition:
    any of them
}