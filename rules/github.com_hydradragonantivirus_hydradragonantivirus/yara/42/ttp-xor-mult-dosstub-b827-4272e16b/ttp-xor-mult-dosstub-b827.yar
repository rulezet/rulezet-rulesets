rule TTP_XOR_MULT_DOSStub_b827 {
  strings:
    $key_b827 = { ec 4f [2] 98 57 [2] df 55 [2] 98 44 [2] d6 48 [2] da 42 [2] cd 49 [2] d6 07 [2] eb }

  condition:
    any of them
}