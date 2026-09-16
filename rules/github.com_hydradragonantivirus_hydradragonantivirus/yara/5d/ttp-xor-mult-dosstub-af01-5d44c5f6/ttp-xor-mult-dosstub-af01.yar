rule TTP_XOR_MULT_DOSStub_af01 {
  strings:
    $key_af01 = { fb 69 [2] 8f 71 [2] c8 73 [2] 8f 62 [2] c1 6e [2] cd 64 [2] da 6f [2] c1 21 [2] fc }

  condition:
    any of them
}