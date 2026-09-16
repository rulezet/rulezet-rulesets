rule TTP_XOR_MULT_DOSStub_13ba {
  strings:
    $key_13ba = { 47 d2 [2] 33 ca [2] 74 c8 [2] 33 d9 [2] 7d d5 [2] 71 df [2] 66 d4 [2] 7d 9a [2] 40 }

  condition:
    any of them
}