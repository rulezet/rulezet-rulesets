rule TTP_XOR_MULT_DOSStub_b897 {
  strings:
    $key_b897 = { ec ff [2] 98 e7 [2] df e5 [2] 98 f4 [2] d6 f8 [2] da f2 [2] cd f9 [2] d6 b7 [2] eb }

  condition:
    any of them
}