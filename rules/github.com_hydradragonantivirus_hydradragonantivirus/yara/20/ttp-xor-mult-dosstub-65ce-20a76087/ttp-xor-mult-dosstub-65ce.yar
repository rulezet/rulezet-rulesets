rule TTP_XOR_MULT_DOSStub_65ce {
  strings:
    $key_65ce = { 31 a6 [2] 45 be [2] 02 bc [2] 45 ad [2] 0b a1 [2] 07 ab [2] 10 a0 [2] 0b ee [2] 36 }

  condition:
    any of them
}