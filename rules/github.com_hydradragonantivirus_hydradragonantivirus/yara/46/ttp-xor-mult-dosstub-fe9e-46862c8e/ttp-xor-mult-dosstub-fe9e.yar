rule TTP_XOR_MULT_DOSStub_fe9e {
  strings:
    $key_fe9e = { aa f6 [2] de ee [2] 99 ec [2] de fd [2] 90 f1 [2] 9c fb [2] 8b f0 [2] 90 be [2] ad }

  condition:
    any of them
}