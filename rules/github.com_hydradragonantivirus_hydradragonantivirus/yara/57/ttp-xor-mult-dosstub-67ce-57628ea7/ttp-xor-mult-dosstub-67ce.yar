rule TTP_XOR_MULT_DOSStub_67ce {
  strings:
    $key_67ce = { 33 a6 [2] 47 be [2] 00 bc [2] 47 ad [2] 09 a1 [2] 05 ab [2] 12 a0 [2] 09 ee [2] 34 }

  condition:
    any of them
}