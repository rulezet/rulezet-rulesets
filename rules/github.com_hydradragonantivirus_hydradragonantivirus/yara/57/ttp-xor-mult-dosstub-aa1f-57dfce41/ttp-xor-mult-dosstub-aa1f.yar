rule TTP_XOR_MULT_DOSStub_aa1f {
  strings:
    $key_aa1f = { fe 77 [2] 8a 6f [2] cd 6d [2] 8a 7c [2] c4 70 [2] c8 7a [2] df 71 [2] c4 3f [2] f9 }

  condition:
    any of them
}