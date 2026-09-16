rule TTP_XOR_MULT_DOSStub_3682 {
  strings:
    $key_3682 = { 62 ea [2] 16 f2 [2] 51 f0 [2] 16 e1 [2] 58 ed [2] 54 e7 [2] 43 ec [2] 58 a2 [2] 65 }

  condition:
    any of them
}