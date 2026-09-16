rule TTP_XOR_MULT_DOSStub_aa6a {
  strings:
    $key_aa6a = { fe 02 [2] 8a 1a [2] cd 18 [2] 8a 09 [2] c4 05 [2] c8 0f [2] df 04 [2] c4 4a [2] f9 }

  condition:
    any of them
}