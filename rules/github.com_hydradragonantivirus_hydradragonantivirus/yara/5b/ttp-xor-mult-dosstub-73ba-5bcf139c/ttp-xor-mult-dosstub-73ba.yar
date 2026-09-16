rule TTP_XOR_MULT_DOSStub_73ba {
  strings:
    $key_73ba = { 27 d2 [2] 53 ca [2] 14 c8 [2] 53 d9 [2] 1d d5 [2] 11 df [2] 06 d4 [2] 1d 9a [2] 20 }

  condition:
    any of them
}