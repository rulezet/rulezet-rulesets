rule TTP_XOR_MULT_DOSStub_2883 {
  strings:
    $key_2883 = { 7c eb [2] 08 f3 [2] 4f f1 [2] 08 e0 [2] 46 ec [2] 4a e6 [2] 5d ed [2] 46 a3 [2] 7b }

  condition:
    any of them
}