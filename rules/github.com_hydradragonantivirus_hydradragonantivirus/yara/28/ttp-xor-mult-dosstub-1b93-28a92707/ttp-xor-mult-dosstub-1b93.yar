rule TTP_XOR_MULT_DOSStub_1b93 {
  strings:
    $key_1b93 = { 4f fb [2] 3b e3 [2] 7c e1 [2] 3b f0 [2] 75 fc [2] 79 f6 [2] 6e fd [2] 75 b3 [2] 48 }

  condition:
    any of them
}