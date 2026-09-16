rule TTP_XOR_MULT_DOSStub_11ce {
  strings:
    $key_11ce = { 45 a6 [2] 31 be [2] 76 bc [2] 31 ad [2] 7f a1 [2] 73 ab [2] 64 a0 [2] 7f ee [2] 42 }

  condition:
    any of them
}