rule TTP_XOR_MULT_DOSStub_0f95 {
  strings:
    $key_0f95 = { 5b fd [2] 2f e5 [2] 68 e7 [2] 2f f6 [2] 61 fa [2] 6d f0 [2] 7a fb [2] 61 b5 [2] 5c }

  condition:
    any of them
}