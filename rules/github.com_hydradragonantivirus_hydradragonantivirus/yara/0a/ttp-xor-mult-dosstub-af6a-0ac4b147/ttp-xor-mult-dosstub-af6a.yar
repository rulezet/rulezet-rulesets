rule TTP_XOR_MULT_DOSStub_af6a {
  strings:
    $key_af6a = { fb 02 [2] 8f 1a [2] c8 18 [2] 8f 09 [2] c1 05 [2] cd 0f [2] da 04 [2] c1 4a [2] fc }

  condition:
    any of them
}