rule TTP_XOR_MULT_DOSStub_3e9e {
  strings:
    $key_3e9e = { 6a f6 [2] 1e ee [2] 59 ec [2] 1e fd [2] 50 f1 [2] 5c fb [2] 4b f0 [2] 50 be [2] 6d }

  condition:
    any of them
}