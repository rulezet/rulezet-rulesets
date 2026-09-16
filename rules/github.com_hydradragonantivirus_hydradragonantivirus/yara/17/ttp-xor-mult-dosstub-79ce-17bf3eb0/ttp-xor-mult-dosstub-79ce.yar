rule TTP_XOR_MULT_DOSStub_79ce {
  strings:
    $key_79ce = { 2d a6 [2] 59 be [2] 1e bc [2] 59 ad [2] 17 a1 [2] 1b ab [2] 0c a0 [2] 17 ee [2] 2a }

  condition:
    any of them
}