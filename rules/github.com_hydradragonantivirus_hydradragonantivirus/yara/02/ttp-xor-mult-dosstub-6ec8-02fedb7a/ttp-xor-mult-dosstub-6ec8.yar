rule TTP_XOR_MULT_DOSStub_6ec8 {
  strings:
    $key_6ec8 = { 3a a0 [2] 4e b8 [2] 09 ba [2] 4e ab [2] 00 a7 [2] 0c ad [2] 1b a6 [2] 00 e8 [2] 3d }

  condition:
    any of them
}