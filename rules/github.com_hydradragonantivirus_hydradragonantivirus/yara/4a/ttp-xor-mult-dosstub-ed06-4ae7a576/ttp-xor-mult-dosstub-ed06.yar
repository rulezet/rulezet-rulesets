rule TTP_XOR_MULT_DOSStub_ed06 {
  strings:
    $key_ed06 = { b9 6e [2] cd 76 [2] 8a 74 [2] cd 65 [2] 83 69 [2] 8f 63 [2] 98 68 [2] 83 26 [2] be }

  condition:
    any of them
}