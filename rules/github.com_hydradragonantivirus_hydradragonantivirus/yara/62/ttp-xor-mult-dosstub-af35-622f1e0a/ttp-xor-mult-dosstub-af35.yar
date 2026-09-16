rule TTP_XOR_MULT_DOSStub_af35 {
  strings:
    $key_af35 = { fb 5d [2] 8f 45 [2] c8 47 [2] 8f 56 [2] c1 5a [2] cd 50 [2] da 5b [2] c1 15 [2] fc }

  condition:
    any of them
}