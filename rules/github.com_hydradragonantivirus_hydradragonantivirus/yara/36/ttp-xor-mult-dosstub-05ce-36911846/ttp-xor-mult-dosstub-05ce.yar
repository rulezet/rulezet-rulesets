rule TTP_XOR_MULT_DOSStub_05ce {
  strings:
    $key_05ce = { 51 a6 [2] 25 be [2] 62 bc [2] 25 ad [2] 6b a1 [2] 67 ab [2] 70 a0 [2] 6b ee [2] 56 }

  condition:
    any of them
}