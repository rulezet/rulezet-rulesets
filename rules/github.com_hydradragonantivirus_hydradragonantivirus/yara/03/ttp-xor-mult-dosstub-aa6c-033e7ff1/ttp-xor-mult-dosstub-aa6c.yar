rule TTP_XOR_MULT_DOSStub_aa6c {
  strings:
    $key_aa6c = { fe 04 [2] 8a 1c [2] cd 1e [2] 8a 0f [2] c4 03 [2] c8 09 [2] df 02 [2] c4 4c [2] f9 }

  condition:
    any of them
}