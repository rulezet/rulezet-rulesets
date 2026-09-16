rule TTP_XOR_MULT_DOSStub_af1d {
  strings:
    $key_af1d = { fb 75 [2] 8f 6d [2] c8 6f [2] 8f 7e [2] c1 72 [2] cd 78 [2] da 73 [2] c1 3d [2] fc }

  condition:
    any of them
}