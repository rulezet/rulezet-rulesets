rule TTP_XOR_MULT_DOSStub_afef {
  strings:
    $key_afef = { fb 87 [2] 8f 9f [2] c8 9d [2] 8f 8c [2] c1 80 [2] cd 8a [2] da 81 [2] c1 cf [2] fc }

  condition:
    any of them
}