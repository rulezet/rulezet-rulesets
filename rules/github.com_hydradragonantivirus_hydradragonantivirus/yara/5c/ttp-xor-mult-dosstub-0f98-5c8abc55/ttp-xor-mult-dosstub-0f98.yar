rule TTP_XOR_MULT_DOSStub_0f98 {
  strings:
    $key_0f98 = { 5b f0 [2] 2f e8 [2] 68 ea [2] 2f fb [2] 61 f7 [2] 6d fd [2] 7a f6 [2] 61 b8 [2] 5c }

  condition:
    any of them
}