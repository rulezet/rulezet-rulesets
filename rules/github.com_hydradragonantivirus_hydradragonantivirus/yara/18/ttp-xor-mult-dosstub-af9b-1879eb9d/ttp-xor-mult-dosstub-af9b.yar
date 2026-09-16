rule TTP_XOR_MULT_DOSStub_af9b {
  strings:
    $key_af9b = { fb f3 [2] 8f eb [2] c8 e9 [2] 8f f8 [2] c1 f4 [2] cd fe [2] da f5 [2] c1 bb [2] fc }

  condition:
    any of them
}