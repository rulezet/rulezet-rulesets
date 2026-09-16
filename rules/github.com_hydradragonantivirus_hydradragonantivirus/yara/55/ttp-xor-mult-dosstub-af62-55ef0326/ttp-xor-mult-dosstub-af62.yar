rule TTP_XOR_MULT_DOSStub_af62 {
  strings:
    $key_af62 = { fb 0a [2] 8f 12 [2] c8 10 [2] 8f 01 [2] c1 0d [2] cd 07 [2] da 0c [2] c1 42 [2] fc }

  condition:
    any of them
}