rule TTP_XOR_MULT_DOSStub_af9c {
  strings:
    $key_af9c = { fb f4 [2] 8f ec [2] c8 ee [2] 8f ff [2] c1 f3 [2] cd f9 [2] da f2 [2] c1 bc [2] fc }

  condition:
    any of them
}