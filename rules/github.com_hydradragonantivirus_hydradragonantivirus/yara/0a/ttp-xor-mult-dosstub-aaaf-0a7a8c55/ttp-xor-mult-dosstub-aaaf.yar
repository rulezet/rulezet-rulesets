rule TTP_XOR_MULT_DOSStub_aaaf {
  strings:
    $key_aaaf = { fe c7 [2] 8a df [2] cd dd [2] 8a cc [2] c4 c0 [2] c8 ca [2] df c1 [2] c4 8f [2] f9 }

  condition:
    any of them
}