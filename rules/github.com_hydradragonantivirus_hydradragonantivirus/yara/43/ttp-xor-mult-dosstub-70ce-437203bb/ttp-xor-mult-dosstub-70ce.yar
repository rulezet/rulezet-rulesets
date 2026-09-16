rule TTP_XOR_MULT_DOSStub_70ce {
  strings:
    $key_70ce = { 24 a6 [2] 50 be [2] 17 bc [2] 50 ad [2] 1e a1 [2] 12 ab [2] 05 a0 [2] 1e ee [2] 23 }

  condition:
    any of them
}