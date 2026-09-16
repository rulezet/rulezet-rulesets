rule TTP_XOR_MULT_DOSStub_26ce {
  strings:
    $key_26ce = { 72 a6 [2] 06 be [2] 41 bc [2] 06 ad [2] 48 a1 [2] 44 ab [2] 53 a0 [2] 48 ee [2] 75 }

  condition:
    any of them
}