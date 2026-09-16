rule TTP_XOR_MULT_DOSStub_00ce {
  strings:
    $key_00ce = { 54 a6 [2] 20 be [2] 67 bc [2] 20 ad [2] 6e a1 [2] 62 ab [2] 75 a0 [2] 6e ee [2] 53 }

  condition:
    any of them
}