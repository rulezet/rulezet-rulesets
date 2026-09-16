rule TTP_XOR_MULT_DOSStub_63ba {
  strings:
    $key_63ba = { 37 d2 [2] 43 ca [2] 04 c8 [2] 43 d9 [2] 0d d5 [2] 01 df [2] 16 d4 [2] 0d 9a [2] 30 }

  condition:
    any of them
}