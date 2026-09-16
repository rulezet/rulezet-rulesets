rule TTP_XOR_MULT_DOSStub_af3d {
  strings:
    $key_af3d = { fb 55 [2] 8f 4d [2] c8 4f [2] 8f 5e [2] c1 52 [2] cd 58 [2] da 53 [2] c1 1d [2] fc }

  condition:
    any of them
}