rule TTP_XOR_MULT_DOSStub_af5d {
  strings:
    $key_af5d = { fb 35 [2] 8f 2d [2] c8 2f [2] 8f 3e [2] c1 32 [2] cd 38 [2] da 33 [2] c1 7d [2] fc }

  condition:
    any of them
}