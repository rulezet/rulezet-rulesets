rule TTP_XOR_MULT_DOSStub_af86 {
  strings:
    $key_af86 = { fb ee [2] 8f f6 [2] c8 f4 [2] 8f e5 [2] c1 e9 [2] cd e3 [2] da e8 [2] c1 a6 [2] fc }

  condition:
    any of them
}