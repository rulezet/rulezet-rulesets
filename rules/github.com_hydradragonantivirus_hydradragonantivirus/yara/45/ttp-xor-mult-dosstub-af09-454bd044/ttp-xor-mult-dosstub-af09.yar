rule TTP_XOR_MULT_DOSStub_af09 {
  strings:
    $key_af09 = { fb 61 [2] 8f 79 [2] c8 7b [2] 8f 6a [2] c1 66 [2] cd 6c [2] da 67 [2] c1 29 [2] fc }

  condition:
    any of them
}