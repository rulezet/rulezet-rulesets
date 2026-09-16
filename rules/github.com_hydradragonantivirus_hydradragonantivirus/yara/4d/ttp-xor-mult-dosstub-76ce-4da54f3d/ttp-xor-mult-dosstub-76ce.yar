rule TTP_XOR_MULT_DOSStub_76ce {
  strings:
    $key_76ce = { 22 a6 [2] 56 be [2] 11 bc [2] 56 ad [2] 18 a1 [2] 14 ab [2] 03 a0 [2] 18 ee [2] 25 }

  condition:
    any of them
}