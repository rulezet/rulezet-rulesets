rule TTP_XOR_MULT_DOSStub_af48 {
  strings:
    $key_af48 = { fb 20 [2] 8f 38 [2] c8 3a [2] 8f 2b [2] c1 27 [2] cd 2d [2] da 26 [2] c1 68 [2] fc }

  condition:
    any of them
}