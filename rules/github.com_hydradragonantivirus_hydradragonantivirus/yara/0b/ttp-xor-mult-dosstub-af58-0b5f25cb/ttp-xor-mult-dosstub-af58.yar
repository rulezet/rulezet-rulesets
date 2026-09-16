rule TTP_XOR_MULT_DOSStub_af58 {
  strings:
    $key_af58 = { fb 30 [2] 8f 28 [2] c8 2a [2] 8f 3b [2] c1 37 [2] cd 3d [2] da 36 [2] c1 78 [2] fc }

  condition:
    any of them
}