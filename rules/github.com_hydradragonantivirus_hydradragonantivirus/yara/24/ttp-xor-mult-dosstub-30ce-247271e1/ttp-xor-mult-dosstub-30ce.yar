rule TTP_XOR_MULT_DOSStub_30ce {
  strings:
    $key_30ce = { 64 a6 [2] 10 be [2] 57 bc [2] 10 ad [2] 5e a1 [2] 52 ab [2] 45 a0 [2] 5e ee [2] 63 }

  condition:
    any of them
}