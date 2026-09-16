rule TTP_XOR_MULT_DOSStub_2f98 {
  strings:
    $key_2f98 = { 7b f0 [2] 0f e8 [2] 48 ea [2] 0f fb [2] 41 f7 [2] 4d fd [2] 5a f6 [2] 41 b8 [2] 7c }

  condition:
    any of them
}