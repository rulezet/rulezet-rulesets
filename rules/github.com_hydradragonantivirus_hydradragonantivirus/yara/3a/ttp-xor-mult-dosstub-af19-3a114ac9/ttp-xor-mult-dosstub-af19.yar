rule TTP_XOR_MULT_DOSStub_af19 {
  strings:
    $key_af19 = { fb 71 [2] 8f 69 [2] c8 6b [2] 8f 7a [2] c1 76 [2] cd 7c [2] da 77 [2] c1 39 [2] fc }

  condition:
    any of them
}