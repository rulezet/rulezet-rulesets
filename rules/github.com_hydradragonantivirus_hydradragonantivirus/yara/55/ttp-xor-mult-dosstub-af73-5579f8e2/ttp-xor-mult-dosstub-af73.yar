rule TTP_XOR_MULT_DOSStub_af73 {
  strings:
    $key_af73 = { fb 1b [2] 8f 03 [2] c8 01 [2] 8f 10 [2] c1 1c [2] cd 16 [2] da 1d [2] c1 53 [2] fc }

  condition:
    any of them
}