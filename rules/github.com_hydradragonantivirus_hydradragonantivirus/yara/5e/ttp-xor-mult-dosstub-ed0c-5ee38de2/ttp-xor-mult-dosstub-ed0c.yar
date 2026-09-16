rule TTP_XOR_MULT_DOSStub_ed0c {
  strings:
    $key_ed0c = { b9 64 [2] cd 7c [2] 8a 7e [2] cd 6f [2] 83 63 [2] 8f 69 [2] 98 62 [2] 83 2c [2] be }

  condition:
    any of them
}