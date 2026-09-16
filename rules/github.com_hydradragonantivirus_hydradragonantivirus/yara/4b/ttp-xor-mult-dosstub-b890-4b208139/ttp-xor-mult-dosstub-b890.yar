rule TTP_XOR_MULT_DOSStub_b890 {
  strings:
    $key_b890 = { ec f8 [2] 98 e0 [2] df e2 [2] 98 f3 [2] d6 ff [2] da f5 [2] cd fe [2] d6 b0 [2] eb }

  condition:
    any of them
}