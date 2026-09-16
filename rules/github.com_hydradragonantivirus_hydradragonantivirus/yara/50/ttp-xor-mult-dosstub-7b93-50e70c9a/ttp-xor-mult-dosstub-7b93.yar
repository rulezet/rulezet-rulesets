rule TTP_XOR_MULT_DOSStub_7b93 {
  strings:
    $key_7b93 = { 2f fb [2] 5b e3 [2] 1c e1 [2] 5b f0 [2] 15 fc [2] 19 f6 [2] 0e fd [2] 15 b3 [2] 28 }

  condition:
    any of them
}