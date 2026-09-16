rule TTP_XOR_MULT_DOSStub_1ad5 {
  strings:
    $key_1ad5 = { 4e bd [2] 3a a5 [2] 7d a7 [2] 3a b6 [2] 74 ba [2] 78 b0 [2] 6f bb [2] 74 f5 [2] 49 }

  condition:
    any of them
}