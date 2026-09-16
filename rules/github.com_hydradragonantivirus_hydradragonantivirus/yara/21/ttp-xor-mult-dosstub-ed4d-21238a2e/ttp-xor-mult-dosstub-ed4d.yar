rule TTP_XOR_MULT_DOSStub_ed4d {
  strings:
    $key_ed4d = { b9 25 [2] cd 3d [2] 8a 3f [2] cd 2e [2] 83 22 [2] 8f 28 [2] 98 23 [2] 83 6d [2] be }

  condition:
    any of them
}