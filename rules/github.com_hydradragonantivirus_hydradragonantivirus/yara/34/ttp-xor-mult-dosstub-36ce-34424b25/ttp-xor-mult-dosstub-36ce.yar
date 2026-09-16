rule TTP_XOR_MULT_DOSStub_36ce {
  strings:
    $key_36ce = { 62 a6 [2] 16 be [2] 51 bc [2] 16 ad [2] 58 a1 [2] 54 ab [2] 43 a0 [2] 58 ee [2] 65 }

  condition:
    any of them
}