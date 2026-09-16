rule TTP_XOR_MULT_DOSStub_ed0d {
  strings:
    $key_ed0d = { b9 65 [2] cd 7d [2] 8a 7f [2] cd 6e [2] 83 62 [2] 8f 68 [2] 98 63 [2] 83 2d [2] be }

  condition:
    any of them
}