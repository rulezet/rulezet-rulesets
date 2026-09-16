rule TTP_XOR_MULT_DOSStub_48c8 {
  strings:
    $key_48c8 = { 1c a0 [2] 68 b8 [2] 2f ba [2] 68 ab [2] 26 a7 [2] 2a ad [2] 3d a6 [2] 26 e8 [2] 1b }

  condition:
    any of them
}