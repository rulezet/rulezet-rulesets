rule TTP_XOR_MULT_DOSStub_61ce {
  strings:
    $key_61ce = { 35 a6 [2] 41 be [2] 06 bc [2] 41 ad [2] 0f a1 [2] 03 ab [2] 14 a0 [2] 0f ee [2] 32 }

  condition:
    any of them
}