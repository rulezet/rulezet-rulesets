rule TTP_XOR_MULT_DOSStub_af6f {
  strings:
    $key_af6f = { fb 07 [2] 8f 1f [2] c8 1d [2] 8f 0c [2] c1 00 [2] cd 0a [2] da 01 [2] c1 4f [2] fc }

  condition:
    any of them
}