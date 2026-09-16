rule TTP_XOR_MULT_DOSStub_aa2f {
  strings:
    $key_aa2f = { fe 47 [2] 8a 5f [2] cd 5d [2] 8a 4c [2] c4 40 [2] c8 4a [2] df 41 [2] c4 0f [2] f9 }

  condition:
    any of them
}