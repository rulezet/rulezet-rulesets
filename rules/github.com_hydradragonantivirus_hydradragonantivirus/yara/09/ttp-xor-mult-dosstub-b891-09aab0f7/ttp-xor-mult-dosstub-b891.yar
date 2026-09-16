rule TTP_XOR_MULT_DOSStub_b891 {
  strings:
    $key_b891 = { ec f9 [2] 98 e1 [2] df e3 [2] 98 f2 [2] d6 fe [2] da f4 [2] cd ff [2] d6 b1 [2] eb }

  condition:
    any of them
}