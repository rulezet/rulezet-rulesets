rule TTP_XOR_MULT_DOSStub_aa7a {
  strings:
    $key_aa7a = { fe 12 [2] 8a 0a [2] cd 08 [2] 8a 19 [2] c4 15 [2] c8 1f [2] df 14 [2] c4 5a [2] f9 }

  condition:
    any of them
}