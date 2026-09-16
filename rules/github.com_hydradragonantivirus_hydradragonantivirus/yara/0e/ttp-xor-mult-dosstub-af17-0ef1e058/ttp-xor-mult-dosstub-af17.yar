rule TTP_XOR_MULT_DOSStub_af17 {
  strings:
    $key_af17 = { fb 7f [2] 8f 67 [2] c8 65 [2] 8f 74 [2] c1 78 [2] cd 72 [2] da 79 [2] c1 37 [2] fc }

  condition:
    any of them
}