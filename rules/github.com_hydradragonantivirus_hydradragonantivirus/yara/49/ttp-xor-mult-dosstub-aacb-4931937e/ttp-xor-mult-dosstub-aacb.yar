rule TTP_XOR_MULT_DOSStub_aacb {
  strings:
    $key_aacb = { fe a3 [2] 8a bb [2] cd b9 [2] 8a a8 [2] c4 a4 [2] c8 ae [2] df a5 [2] c4 eb [2] f9 }

  condition:
    any of them
}