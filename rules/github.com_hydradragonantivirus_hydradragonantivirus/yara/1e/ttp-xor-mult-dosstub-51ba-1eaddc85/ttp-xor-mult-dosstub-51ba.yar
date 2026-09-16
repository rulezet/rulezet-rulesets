rule TTP_XOR_MULT_DOSStub_51ba {
  strings:
    $key_51ba = { 05 d2 [2] 71 ca [2] 36 c8 [2] 71 d9 [2] 3f d5 [2] 33 df [2] 24 d4 [2] 3f 9a [2] 02 }

  condition:
    any of them
}