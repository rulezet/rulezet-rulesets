rule TTP_XOR_MULT_DOSStub_af45 {
  strings:
    $key_af45 = { fb 2d [2] 8f 35 [2] c8 37 [2] 8f 26 [2] c1 2a [2] cd 20 [2] da 2b [2] c1 65 [2] fc }

  condition:
    any of them
}