rule TTP_XOR_MULT_DOSStub_afdd {
  strings:
    $key_afdd = { fb b5 [2] 8f ad [2] c8 af [2] 8f be [2] c1 b2 [2] cd b8 [2] da b3 [2] c1 fd [2] fc }

  condition:
    any of them
}