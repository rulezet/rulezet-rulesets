rule TTP_XOR_MULT_DOSStub_7e9e {
  strings:
    $key_7e9e = { 2a f6 [2] 5e ee [2] 19 ec [2] 5e fd [2] 10 f1 [2] 1c fb [2] 0b f0 [2] 10 be [2] 2d }

  condition:
    any of them
}