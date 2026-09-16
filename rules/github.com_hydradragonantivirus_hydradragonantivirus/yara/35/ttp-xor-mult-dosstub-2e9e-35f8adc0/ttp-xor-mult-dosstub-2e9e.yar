rule TTP_XOR_MULT_DOSStub_2e9e {
  strings:
    $key_2e9e = { 7a f6 [2] 0e ee [2] 49 ec [2] 0e fd [2] 40 f1 [2] 4c fb [2] 5b f0 [2] 40 be [2] 7d }

  condition:
    any of them
}