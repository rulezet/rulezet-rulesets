rule TTP_XOR_MULT_DOSStub_ed23 {
  strings:
    $key_ed23 = { b9 4b [2] cd 53 [2] 8a 51 [2] cd 40 [2] 83 4c [2] 8f 46 [2] 98 4d [2] 83 03 [2] be }

  condition:
    any of them
}