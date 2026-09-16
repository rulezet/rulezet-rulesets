rule TTP_XOR_MULT_DOSStub_af2a {
  strings:
    $key_af2a = { fb 42 [2] 8f 5a [2] c8 58 [2] 8f 49 [2] c1 45 [2] cd 4f [2] da 44 [2] c1 0a [2] fc }

  condition:
    any of them
}