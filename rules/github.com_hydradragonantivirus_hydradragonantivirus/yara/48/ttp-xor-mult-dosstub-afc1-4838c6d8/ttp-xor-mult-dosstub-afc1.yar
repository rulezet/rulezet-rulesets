rule TTP_XOR_MULT_DOSStub_afc1 {
  strings:
    $key_afc1 = { fb a9 [2] 8f b1 [2] c8 b3 [2] 8f a2 [2] c1 ae [2] cd a4 [2] da af [2] c1 e1 [2] fc }

  condition:
    any of them
}