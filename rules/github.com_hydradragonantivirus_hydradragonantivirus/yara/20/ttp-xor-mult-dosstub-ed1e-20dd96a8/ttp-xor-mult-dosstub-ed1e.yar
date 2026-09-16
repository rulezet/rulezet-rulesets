rule TTP_XOR_MULT_DOSStub_ed1e {
  strings:
    $key_ed1e = { b9 76 [2] cd 6e [2] 8a 6c [2] cd 7d [2] 83 71 [2] 8f 7b [2] 98 70 [2] 83 3e [2] be }

  condition:
    any of them
}