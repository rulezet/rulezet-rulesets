rule TTP_XOR_MULT_DOSStub_af64 {
  strings:
    $key_af64 = { fb 0c [2] 8f 14 [2] c8 16 [2] 8f 07 [2] c1 0b [2] cd 01 [2] da 0a [2] c1 44 [2] fc }

  condition:
    any of them
}