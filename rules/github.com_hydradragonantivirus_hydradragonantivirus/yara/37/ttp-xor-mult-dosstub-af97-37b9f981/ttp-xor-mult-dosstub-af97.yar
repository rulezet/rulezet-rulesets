rule TTP_XOR_MULT_DOSStub_af97 {
  strings:
    $key_af97 = { fb ff [2] 8f e7 [2] c8 e5 [2] 8f f4 [2] c1 f8 [2] cd f2 [2] da f9 [2] c1 b7 [2] fc }

  condition:
    any of them
}