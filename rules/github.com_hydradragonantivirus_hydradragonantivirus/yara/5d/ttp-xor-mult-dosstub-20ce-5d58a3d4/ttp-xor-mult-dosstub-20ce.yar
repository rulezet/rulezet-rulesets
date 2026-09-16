rule TTP_XOR_MULT_DOSStub_20ce {
  strings:
    $key_20ce = { 74 a6 [2] 00 be [2] 47 bc [2] 00 ad [2] 4e a1 [2] 42 ab [2] 55 a0 [2] 4e ee [2] 73 }

  condition:
    any of them
}