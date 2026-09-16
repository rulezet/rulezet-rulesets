rule TTP_XOR_MULT_DOSStub_af92 {
  strings:
    $key_af92 = { fb fa [2] 8f e2 [2] c8 e0 [2] 8f f1 [2] c1 fd [2] cd f7 [2] da fc [2] c1 b2 [2] fc }

  condition:
    any of them
}