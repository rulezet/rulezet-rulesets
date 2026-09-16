rule TTP_XOR_MULT_DOSStub_af14 {
  strings:
    $key_af14 = { fb 7c [2] 8f 64 [2] c8 66 [2] 8f 77 [2] c1 7b [2] cd 71 [2] da 7a [2] c1 34 [2] fc }

  condition:
    any of them
}