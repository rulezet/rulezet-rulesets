rule TTP_XOR_MULT_DOSStub_5f98 {
  strings:
    $key_5f98 = { 0b f0 [2] 7f e8 [2] 38 ea [2] 7f fb [2] 31 f7 [2] 3d fd [2] 2a f6 [2] 31 b8 [2] 0c }

  condition:
    any of them
}