rule TTP_XOR_MULT_DOSStub_af79 {
  strings:
    $key_af79 = { fb 11 [2] 8f 09 [2] c8 0b [2] 8f 1a [2] c1 16 [2] cd 1c [2] da 17 [2] c1 59 [2] fc }

  condition:
    any of them
}