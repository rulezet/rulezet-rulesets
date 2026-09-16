rule TTP_XOR_MULT_DOSStub_ed5d {
  strings:
    $key_ed5d = { b9 35 [2] cd 2d [2] 8a 2f [2] cd 3e [2] 83 32 [2] 8f 38 [2] 98 33 [2] 83 7d [2] be }

  condition:
    any of them
}