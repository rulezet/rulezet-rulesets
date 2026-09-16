rule TTP_XOR_MULT_DOSStub_aa5e {
  strings:
    $key_aa5e = { fe 36 [2] 8a 2e [2] cd 2c [2] 8a 3d [2] c4 31 [2] c8 3b [2] df 30 [2] c4 7e [2] f9 }

  condition:
    any of them
}