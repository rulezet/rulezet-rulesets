rule TTP_XOR_MULT_DOSStub_afe4 {
  strings:
    $key_afe4 = { fb 8c [2] 8f 94 [2] c8 96 [2] 8f 87 [2] c1 8b [2] cd 81 [2] da 8a [2] c1 c4 [2] fc }

  condition:
    any of them
}