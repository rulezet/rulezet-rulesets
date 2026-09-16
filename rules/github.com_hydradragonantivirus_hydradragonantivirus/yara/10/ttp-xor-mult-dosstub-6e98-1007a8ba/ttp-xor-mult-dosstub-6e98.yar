rule TTP_XOR_MULT_DOSStub_6e98 {
  strings:
    $key_6e98 = { 3a f0 [2] 4e e8 [2] 09 ea [2] 4e fb [2] 00 f7 [2] 0c fd [2] 1b f6 [2] 00 b8 [2] 3d }

  condition:
    any of them
}