rule TTP_XOR_MULT_DOSStub_af3f {
  strings:
    $key_af3f = { fb 57 [2] 8f 4f [2] c8 4d [2] 8f 5c [2] c1 50 [2] cd 5a [2] da 51 [2] c1 1f [2] fc }

  condition:
    any of them
}