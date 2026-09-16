rule TTP_XOR_MULT_DOSStub_7d9e {
  strings:
    $key_7d9e = { 29 f6 [2] 5d ee [2] 1a ec [2] 5d fd [2] 13 f1 [2] 1f fb [2] 08 f0 [2] 13 be [2] 2e }

  condition:
    any of them
}