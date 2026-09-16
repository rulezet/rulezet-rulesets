rule TTP_XOR_MULT_DOSStub_68ce {
  strings:
    $key_68ce = { 3c a6 [2] 48 be [2] 0f bc [2] 48 ad [2] 06 a1 [2] 0a ab [2] 1d a0 [2] 06 ee [2] 3b }

  condition:
    any of them
}