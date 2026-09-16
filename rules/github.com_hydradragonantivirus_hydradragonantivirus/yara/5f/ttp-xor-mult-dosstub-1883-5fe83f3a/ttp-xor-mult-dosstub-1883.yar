rule TTP_XOR_MULT_DOSStub_1883 {
  strings:
    $key_1883 = { 4c eb [2] 38 f3 [2] 7f f1 [2] 38 e0 [2] 76 ec [2] 7a e6 [2] 6d ed [2] 76 a3 [2] 4b }

  condition:
    any of them
}