rule TTP_XOR_MULT_DOSStub_af22 {
  strings:
    $key_af22 = { fb 4a [2] 8f 52 [2] c8 50 [2] 8f 41 [2] c1 4d [2] cd 47 [2] da 4c [2] c1 02 [2] fc }

  condition:
    any of them
}