rule TTP_XOR_MULT_DOSStub_06ce {
  strings:
    $key_06ce = { 52 a6 [2] 26 be [2] 61 bc [2] 26 ad [2] 68 a1 [2] 64 ab [2] 73 a0 [2] 68 ee [2] 55 }

  condition:
    any of them
}