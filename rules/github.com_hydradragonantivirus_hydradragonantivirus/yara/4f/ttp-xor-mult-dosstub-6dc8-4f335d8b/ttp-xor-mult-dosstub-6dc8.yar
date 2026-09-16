rule TTP_XOR_MULT_DOSStub_6dc8 {
  strings:
    $key_6dc8 = { 39 a0 [2] 4d b8 [2] 0a ba [2] 4d ab [2] 03 a7 [2] 0f ad [2] 18 a6 [2] 03 e8 [2] 3e }

  condition:
    any of them
}