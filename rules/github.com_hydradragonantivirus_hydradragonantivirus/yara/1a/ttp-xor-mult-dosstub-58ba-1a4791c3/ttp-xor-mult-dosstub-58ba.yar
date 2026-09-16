rule TTP_XOR_MULT_DOSStub_58ba {
  strings:
    $key_58ba = { 0c d2 [2] 78 ca [2] 3f c8 [2] 78 d9 [2] 36 d5 [2] 3a df [2] 2d d4 [2] 36 9a [2] 0b }

  condition:
    any of them
}