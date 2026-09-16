rule TTP_XOR_MULT_DOSStub_afdb {
  strings:
    $key_afdb = { fb b3 [2] 8f ab [2] c8 a9 [2] 8f b8 [2] c1 b4 [2] cd be [2] da b5 [2] c1 fb [2] fc }

  condition:
    any of them
}