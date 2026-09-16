rule TTP_XOR_MULT_DOSStub_af7f {
  strings:
    $key_af7f = { fb 17 [2] 8f 0f [2] c8 0d [2] 8f 1c [2] c1 10 [2] cd 1a [2] da 11 [2] c1 5f [2] fc }

  condition:
    any of them
}