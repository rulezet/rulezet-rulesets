rule TTP_XOR_MULT_DOSStub_6895 {
  strings:
    $key_6895 = { 3c fd [2] 48 e5 [2] 0f e7 [2] 48 f6 [2] 06 fa [2] 0a f0 [2] 1d fb [2] 06 b5 [2] 3b }

  condition:
    any of them
}