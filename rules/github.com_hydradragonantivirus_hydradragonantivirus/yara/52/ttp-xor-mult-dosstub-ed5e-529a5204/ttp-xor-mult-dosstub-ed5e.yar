rule TTP_XOR_MULT_DOSStub_ed5e {
  strings:
    $key_ed5e = { b9 36 [2] cd 2e [2] 8a 2c [2] cd 3d [2] 83 31 [2] 8f 3b [2] 98 30 [2] 83 7e [2] be }

  condition:
    any of them
}