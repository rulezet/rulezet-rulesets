rule TTP_XOR_MULT_DOSStub_42ce {
  strings:
    $key_42ce = { 16 a6 [2] 62 be [2] 25 bc [2] 62 ad [2] 2c a1 [2] 20 ab [2] 37 a0 [2] 2c ee [2] 11 }

  condition:
    any of them
}