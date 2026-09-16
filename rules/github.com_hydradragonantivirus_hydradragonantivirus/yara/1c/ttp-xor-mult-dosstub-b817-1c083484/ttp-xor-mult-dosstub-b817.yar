rule TTP_XOR_MULT_DOSStub_b817 {
  strings:
    $key_b817 = { ec 7f [2] 98 67 [2] df 65 [2] 98 74 [2] d6 78 [2] da 72 [2] cd 79 [2] d6 37 [2] eb }

  condition:
    any of them
}