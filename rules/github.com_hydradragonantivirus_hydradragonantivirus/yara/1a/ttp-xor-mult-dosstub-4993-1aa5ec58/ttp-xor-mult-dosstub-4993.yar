rule TTP_XOR_MULT_DOSStub_4993 {
  strings:
    $key_4993 = { 1d fb [2] 69 e3 [2] 2e e1 [2] 69 f0 [2] 27 fc [2] 2b f6 [2] 3c fd [2] 27 b3 [2] 1a }

  condition:
    any of them
}