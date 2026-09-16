rule TTP_XOR_MULT_DOSStub_6883 {
  strings:
    $key_6883 = { 3c eb [2] 48 f3 [2] 0f f1 [2] 48 e0 [2] 06 ec [2] 0a e6 [2] 1d ed [2] 06 a3 [2] 3b }

  condition:
    any of them
}