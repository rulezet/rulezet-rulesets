rule TTP_XOR_MULT_DOSStub_ed2e {
  strings:
    $key_ed2e = { b9 46 [2] cd 5e [2] 8a 5c [2] cd 4d [2] 83 41 [2] 8f 4b [2] 98 40 [2] 83 0e [2] be }

  condition:
    any of them
}