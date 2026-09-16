rule TTP_XOR_MULT_DOSStub_ed0e {
  strings:
    $key_ed0e = { b9 66 [2] cd 7e [2] 8a 7c [2] cd 6d [2] 83 61 [2] 8f 6b [2] 98 60 [2] 83 2e [2] be }

  condition:
    any of them
}