rule TTP_XOR_MULT_DOSStub_59b4 {
  strings:
    $key_59b4 = { 0d dc [2] 79 c4 [2] 3e c6 [2] 79 d7 [2] 37 db [2] 3b d1 [2] 2c da [2] 37 94 [2] 0a }

  condition:
    any of them
}