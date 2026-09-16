rule TTP_XOR_MULT_DOSStub_af60 {
  strings:
    $key_af60 = { fb 08 [2] 8f 10 [2] c8 12 [2] 8f 03 [2] c1 0f [2] cd 05 [2] da 0e [2] c1 40 [2] fc }

  condition:
    any of them
}