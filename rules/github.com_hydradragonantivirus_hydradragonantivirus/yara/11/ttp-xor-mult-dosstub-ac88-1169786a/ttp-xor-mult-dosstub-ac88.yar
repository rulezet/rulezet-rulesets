rule TTP_XOR_MULT_DOSStub_ac88 {
  strings:
    $key_ac88 = { f8 e0 [2] 8c f8 [2] cb fa [2] 8c eb [2] c2 e7 [2] ce ed [2] d9 e6 [2] c2 a8 [2] ff }

  condition:
    any of them
}