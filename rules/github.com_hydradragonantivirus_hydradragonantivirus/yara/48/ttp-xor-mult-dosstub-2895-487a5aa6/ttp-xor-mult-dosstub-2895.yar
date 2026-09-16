rule TTP_XOR_MULT_DOSStub_2895 {
  strings:
    $key_2895 = { 7c fd [2] 08 e5 [2] 4f e7 [2] 08 f6 [2] 46 fa [2] 4a f0 [2] 5d fb [2] 46 b5 [2] 7b }

  condition:
    any of them
}