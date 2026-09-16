rule TTP_XOR_MULT_DOSStub_af4d {
  strings:
    $key_af4d = { fb 25 [2] 8f 3d [2] c8 3f [2] 8f 2e [2] c1 22 [2] cd 28 [2] da 23 [2] c1 6d [2] fc }

  condition:
    any of them
}