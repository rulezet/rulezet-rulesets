rule TTP_XOR_MULT_DOSStub_50ce {
  strings:
    $key_50ce = { 04 a6 [2] 70 be [2] 37 bc [2] 70 ad [2] 3e a1 [2] 32 ab [2] 25 a0 [2] 3e ee [2] 03 }

  condition:
    any of them
}