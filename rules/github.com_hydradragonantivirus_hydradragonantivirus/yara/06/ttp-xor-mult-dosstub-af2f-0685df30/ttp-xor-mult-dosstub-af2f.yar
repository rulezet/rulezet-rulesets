rule TTP_XOR_MULT_DOSStub_af2f {
  strings:
    $key_af2f = { fb 47 [2] 8f 5f [2] c8 5d [2] 8f 4c [2] c1 40 [2] cd 4a [2] da 41 [2] c1 0f [2] fc }

  condition:
    any of them
}