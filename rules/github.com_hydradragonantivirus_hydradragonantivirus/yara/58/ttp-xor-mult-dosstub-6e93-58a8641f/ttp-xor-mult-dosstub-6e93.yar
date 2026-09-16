rule TTP_XOR_MULT_DOSStub_6e93 {
  strings:
    $key_6e93 = { 3a fb [2] 4e e3 [2] 09 e1 [2] 4e f0 [2] 00 fc [2] 0c f6 [2] 1b fd [2] 00 b3 [2] 3d }

  condition:
    any of them
}