rule TTP_XOR_MULT_DOSStub_48d4 {
  strings:
    $key_48d4 = { 1c bc [2] 68 a4 [2] 2f a6 [2] 68 b7 [2] 26 bb [2] 2a b1 [2] 3d ba [2] 26 f4 [2] 1b }

  condition:
    any of them
}