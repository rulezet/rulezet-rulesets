rule TTP_XOR_MULT_DOSStub_68c8 {
  strings:
    $key_68c8 = { 3c a0 [2] 48 b8 [2] 0f ba [2] 48 ab [2] 06 a7 [2] 0a ad [2] 1d a6 [2] 06 e8 [2] 3b }

  condition:
    any of them
}