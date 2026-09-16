rule TTP_XOR_MULT_DOSStub_affc {
  strings:
    $key_affc = { fb 94 [2] 8f 8c [2] c8 8e [2] 8f 9f [2] c1 93 [2] cd 99 [2] da 92 [2] c1 dc [2] fc }

  condition:
    any of them
}