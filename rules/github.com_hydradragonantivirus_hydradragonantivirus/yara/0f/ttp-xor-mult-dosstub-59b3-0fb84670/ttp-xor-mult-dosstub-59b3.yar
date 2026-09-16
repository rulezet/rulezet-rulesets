rule TTP_XOR_MULT_DOSStub_59b3 {
  strings:
    $key_59b3 = { 0d db [2] 79 c3 [2] 3e c1 [2] 79 d0 [2] 37 dc [2] 3b d6 [2] 2c dd [2] 37 93 [2] 0a }

  condition:
    any of them
}