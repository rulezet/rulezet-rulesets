rule TTP_XOR_MULT_DOSStub_af39 {
  strings:
    $key_af39 = { fb 51 [2] 8f 49 [2] c8 4b [2] 8f 5a [2] c1 56 [2] cd 5c [2] da 57 [2] c1 19 [2] fc }

  condition:
    any of them
}