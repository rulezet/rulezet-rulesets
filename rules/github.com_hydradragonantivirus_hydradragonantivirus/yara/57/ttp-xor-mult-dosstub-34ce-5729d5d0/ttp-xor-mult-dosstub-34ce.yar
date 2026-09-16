rule TTP_XOR_MULT_DOSStub_34ce {
  strings:
    $key_34ce = { 60 a6 [2] 14 be [2] 53 bc [2] 14 ad [2] 5a a1 [2] 56 ab [2] 41 a0 [2] 5a ee [2] 67 }

  condition:
    any of them
}