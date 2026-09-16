rule TTP_XOR_MULT_DOSStub_ed0b {
  strings:
    $key_ed0b = { b9 63 [2] cd 7b [2] 8a 79 [2] cd 68 [2] 83 64 [2] 8f 6e [2] 98 65 [2] 83 2b [2] be }

  condition:
    any of them
}