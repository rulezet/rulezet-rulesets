rule TTP_XOR_MULT_DOSStub_ee9e {
  strings:
    $key_ee9e = { ba f6 [2] ce ee [2] 89 ec [2] ce fd [2] 80 f1 [2] 8c fb [2] 9b f0 [2] 80 be [2] bd }

  condition:
    any of them
}