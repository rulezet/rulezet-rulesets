rule TTP_XOR_MULT_DOSStub_aaba {
  strings:
    $key_aaba = { fe d2 [2] 8a ca [2] cd c8 [2] 8a d9 [2] c4 d5 [2] c8 df [2] df d4 [2] c4 9a [2] f9 }

  condition:
    any of them
}