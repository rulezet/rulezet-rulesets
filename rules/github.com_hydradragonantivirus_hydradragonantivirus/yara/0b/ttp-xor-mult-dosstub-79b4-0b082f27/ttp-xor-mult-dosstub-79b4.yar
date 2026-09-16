rule TTP_XOR_MULT_DOSStub_79b4 {
  strings:
    $key_79b4 = { 2d dc [2] 59 c4 [2] 1e c6 [2] 59 d7 [2] 17 db [2] 1b d1 [2] 0c da [2] 17 94 [2] 2a }

  condition:
    any of them
}