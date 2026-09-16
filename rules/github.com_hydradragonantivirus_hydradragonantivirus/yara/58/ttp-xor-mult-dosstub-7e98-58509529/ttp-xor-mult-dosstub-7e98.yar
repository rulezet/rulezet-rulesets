rule TTP_XOR_MULT_DOSStub_7e98 {
  strings:
    $key_7e98 = { 2a f0 [2] 5e e8 [2] 19 ea [2] 5e fb [2] 10 f7 [2] 1c fd [2] 0b f6 [2] 10 b8 [2] 2d }

  condition:
    any of them
}