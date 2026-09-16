rule TTP_XOR_MULT_DOSStub_ed6d {
  strings:
    $key_ed6d = { b9 05 [2] cd 1d [2] 8a 1f [2] cd 0e [2] 83 02 [2] 8f 08 [2] 98 03 [2] 83 4d [2] be }

  condition:
    any of them
}