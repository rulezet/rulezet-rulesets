rule TTP_XOR_MULT_DOSStub_ed52 {
  strings:
    $key_ed52 = { b9 3a [2] cd 22 [2] 8a 20 [2] cd 31 [2] 83 3d [2] 8f 37 [2] 98 3c [2] 83 72 [2] be }

  condition:
    any of them
}