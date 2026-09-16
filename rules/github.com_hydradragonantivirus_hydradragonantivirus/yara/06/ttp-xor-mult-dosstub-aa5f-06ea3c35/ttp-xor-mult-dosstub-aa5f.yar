rule TTP_XOR_MULT_DOSStub_aa5f {
  strings:
    $key_aa5f = { fe 37 [2] 8a 2f [2] cd 2d [2] 8a 3c [2] c4 30 [2] c8 3a [2] df 31 [2] c4 7f [2] f9 }

  condition:
    any of them
}