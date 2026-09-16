rule TTP_XOR_MULT_DOSStub_aa3d {
  strings:
    $key_aa3d = { fe 55 [2] 8a 4d [2] cd 4f [2] 8a 5e [2] c4 52 [2] c8 58 [2] df 53 [2] c4 1d [2] f9 }

  condition:
    any of them
}