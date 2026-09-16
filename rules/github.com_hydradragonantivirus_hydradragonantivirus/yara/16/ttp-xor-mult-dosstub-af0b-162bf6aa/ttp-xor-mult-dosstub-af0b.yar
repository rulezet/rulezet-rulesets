rule TTP_XOR_MULT_DOSStub_af0b {
  strings:
    $key_af0b = { fb 63 [2] 8f 7b [2] c8 79 [2] 8f 68 [2] c1 64 [2] cd 6e [2] da 65 [2] c1 2b [2] fc }

  condition:
    any of them
}