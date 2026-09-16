rule TTP_XOR_MULT_DOSStub_afec {
  strings:
    $key_afec = { fb 84 [2] 8f 9c [2] c8 9e [2] 8f 8f [2] c1 83 [2] cd 89 [2] da 82 [2] c1 cc [2] fc }

  condition:
    any of them
}