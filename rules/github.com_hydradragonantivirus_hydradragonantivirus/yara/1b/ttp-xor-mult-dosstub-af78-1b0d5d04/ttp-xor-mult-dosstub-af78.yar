rule TTP_XOR_MULT_DOSStub_af78 {
  strings:
    $key_af78 = { fb 10 [2] 8f 08 [2] c8 0a [2] 8f 1b [2] c1 17 [2] cd 1d [2] da 16 [2] c1 58 [2] fc }

  condition:
    any of them
}