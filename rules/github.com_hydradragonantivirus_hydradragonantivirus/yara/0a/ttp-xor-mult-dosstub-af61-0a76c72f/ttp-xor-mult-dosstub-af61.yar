rule TTP_XOR_MULT_DOSStub_af61 {
  strings:
    $key_af61 = { fb 09 [2] 8f 11 [2] c8 13 [2] 8f 02 [2] c1 0e [2] cd 04 [2] da 0f [2] c1 41 [2] fc }

  condition:
    any of them
}