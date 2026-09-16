rule TTP_XOR_MULT_DOSStub_28b7 {
  strings:
    $key_28b7 = { 7c df [2] 08 c7 [2] 4f c5 [2] 08 d4 [2] 46 d8 [2] 4a d2 [2] 5d d9 [2] 46 97 [2] 7b }

  condition:
    any of them
}