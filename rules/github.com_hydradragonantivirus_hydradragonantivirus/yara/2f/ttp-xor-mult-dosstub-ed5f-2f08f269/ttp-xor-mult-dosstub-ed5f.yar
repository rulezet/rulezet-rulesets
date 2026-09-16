rule TTP_XOR_MULT_DOSStub_ed5f {
  strings:
    $key_ed5f = { b9 37 [2] cd 2f [2] 8a 2d [2] cd 3c [2] 83 30 [2] 8f 3a [2] 98 31 [2] 83 7f [2] be }

  condition:
    any of them
}