rule TTP_XOR_MULT_DOSStub_b877 {
  strings:
    $key_b877 = { ec 1f [2] 98 07 [2] df 05 [2] 98 14 [2] d6 18 [2] da 12 [2] cd 19 [2] d6 57 [2] eb }

  condition:
    any of them
}