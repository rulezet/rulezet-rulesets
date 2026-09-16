rule TTP_XOR_MULT_DOSStub_ed12 {
  strings:
    $key_ed12 = { b9 7a [2] cd 62 [2] 8a 60 [2] cd 71 [2] 83 7d [2] 8f 77 [2] 98 7c [2] 83 32 [2] be }

  condition:
    any of them
}