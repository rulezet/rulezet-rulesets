rule TTP_XOR_MULT_DOSStub_ed6f {
  strings:
    $key_ed6f = { b9 07 [2] cd 1f [2] 8a 1d [2] cd 0c [2] 83 00 [2] 8f 0a [2] 98 01 [2] 83 4f [2] be }

  condition:
    any of them
}