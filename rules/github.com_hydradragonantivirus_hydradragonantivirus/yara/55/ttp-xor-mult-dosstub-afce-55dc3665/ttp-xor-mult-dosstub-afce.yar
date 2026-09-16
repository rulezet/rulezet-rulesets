rule TTP_XOR_MULT_DOSStub_afce {
  strings:
    $key_afce = { fb a6 [2] 8f be [2] c8 bc [2] 8f ad [2] c1 a1 [2] cd ab [2] da a0 [2] c1 ee [2] fc }

  condition:
    any of them
}