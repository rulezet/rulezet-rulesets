rule TTP_XOR_MULT_DOSStub_b830 {
  strings:
    $key_b830 = { ec 58 [2] 98 40 [2] df 42 [2] 98 53 [2] d6 5f [2] da 55 [2] cd 5e [2] d6 10 [2] eb }

  condition:
    any of them
}