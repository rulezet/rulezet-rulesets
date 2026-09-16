rule TTP_XOR_MULT_DOSStub_4885 {
  strings:
    $key_4885 = { 1c ed [2] 68 f5 [2] 2f f7 [2] 68 e6 [2] 26 ea [2] 2a e0 [2] 3d eb [2] 26 a5 [2] 1b }

  condition:
    any of them
}