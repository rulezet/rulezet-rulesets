rule TTP_XOR_MULT_DOSStub_af30 {
  strings:
    $key_af30 = { fb 58 [2] 8f 40 [2] c8 42 [2] 8f 53 [2] c1 5f [2] cd 55 [2] da 5e [2] c1 10 [2] fc }

  condition:
    any of them
}