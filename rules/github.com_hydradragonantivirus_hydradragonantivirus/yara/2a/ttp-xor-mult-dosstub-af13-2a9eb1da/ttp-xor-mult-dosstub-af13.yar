rule TTP_XOR_MULT_DOSStub_af13 {
  strings:
    $key_af13 = { fb 7b [2] 8f 63 [2] c8 61 [2] 8f 70 [2] c1 7c [2] cd 76 [2] da 7d [2] c1 33 [2] fc }

  condition:
    any of them
}