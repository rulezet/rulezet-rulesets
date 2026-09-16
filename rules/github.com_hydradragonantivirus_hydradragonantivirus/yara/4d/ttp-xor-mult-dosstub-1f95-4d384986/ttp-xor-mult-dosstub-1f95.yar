rule TTP_XOR_MULT_DOSStub_1f95 {
  strings:
    $key_1f95 = { 4b fd [2] 3f e5 [2] 78 e7 [2] 3f f6 [2] 71 fa [2] 7d f0 [2] 6a fb [2] 71 b5 [2] 4c }

  condition:
    any of them
}