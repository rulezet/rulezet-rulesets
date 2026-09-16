rule TTP_XOR_MULT_DOSStub_ed28 {
  strings:
    $key_ed28 = { b9 40 [2] cd 58 [2] 8a 5a [2] cd 4b [2] 83 47 [2] 8f 4d [2] 98 46 [2] 83 08 [2] be }

  condition:
    any of them
}