rule TTP_XOR_MULT_DOSStub_aa3c {
  strings:
    $key_aa3c = { fe 54 [2] 8a 4c [2] cd 4e [2] 8a 5f [2] c4 53 [2] c8 59 [2] df 52 [2] c4 1c [2] f9 }

  condition:
    any of them
}