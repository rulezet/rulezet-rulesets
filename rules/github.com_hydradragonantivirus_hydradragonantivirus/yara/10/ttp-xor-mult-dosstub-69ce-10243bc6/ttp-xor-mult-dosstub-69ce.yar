rule TTP_XOR_MULT_DOSStub_69ce {
  strings:
    $key_69ce = { 3d a6 [2] 49 be [2] 0e bc [2] 49 ad [2] 07 a1 [2] 0b ab [2] 1c a0 [2] 07 ee [2] 3a }

  condition:
    any of them
}