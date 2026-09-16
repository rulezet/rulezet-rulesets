rule TTP_XOR_MULT_DOSStub_1f98 {
  strings:
    $key_1f98 = { 4b f0 [2] 3f e8 [2] 78 ea [2] 3f fb [2] 71 f7 [2] 7d fd [2] 6a f6 [2] 71 b8 [2] 4c }

  condition:
    any of them
}