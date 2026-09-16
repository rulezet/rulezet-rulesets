rule TTP_XOR_MULT_DOSStub_aa0a {
  strings:
    $key_aa0a = { fe 62 [2] 8a 7a [2] cd 78 [2] 8a 69 [2] c4 65 [2] c8 6f [2] df 64 [2] c4 2a [2] f9 }

  condition:
    any of them
}