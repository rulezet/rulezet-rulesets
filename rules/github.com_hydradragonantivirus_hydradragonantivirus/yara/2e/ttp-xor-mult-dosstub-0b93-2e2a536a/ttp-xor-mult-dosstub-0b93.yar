rule TTP_XOR_MULT_DOSStub_0b93 {
  strings:
    $key_0b93 = { 5f fb [2] 2b e3 [2] 6c e1 [2] 2b f0 [2] 65 fc [2] 69 f6 [2] 7e fd [2] 65 b3 [2] 58 }

  condition:
    any of them
}