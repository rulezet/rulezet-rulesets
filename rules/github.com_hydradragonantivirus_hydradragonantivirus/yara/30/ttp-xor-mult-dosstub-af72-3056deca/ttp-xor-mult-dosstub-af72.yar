rule TTP_XOR_MULT_DOSStub_af72 {
  strings:
    $key_af72 = { fb 1a [2] 8f 02 [2] c8 00 [2] 8f 11 [2] c1 1d [2] cd 17 [2] da 1c [2] c1 52 [2] fc }

  condition:
    any of them
}