rule TTP_XOR_MULT_DOSStub_17ce {
  strings:
    $key_17ce = { 43 a6 [2] 37 be [2] 70 bc [2] 37 ad [2] 79 a1 [2] 75 ab [2] 62 a0 [2] 79 ee [2] 44 }

  condition:
    any of them
}