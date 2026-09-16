rule TTP_XOR_MULT_DOSStub_3895 {
  strings:
    $key_3895 = { 6c fd [2] 18 e5 [2] 5f e7 [2] 18 f6 [2] 56 fa [2] 5a f0 [2] 4d fb [2] 56 b5 [2] 6b }

  condition:
    any of them
}