rule TTP_XOR_MULT_DOSStub_af3b {
  strings:
    $key_af3b = { fb 53 [2] 8f 4b [2] c8 49 [2] 8f 58 [2] c1 54 [2] cd 5e [2] da 55 [2] c1 1b [2] fc }

  condition:
    any of them
}