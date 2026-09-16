rule TTP_XOR_MULT_DOSStub_eedb {
  strings:
    $key_eedb = { ba b3 [2] ce ab [2] 89 a9 [2] ce b8 [2] 80 b4 [2] 8c be [2] 9b b5 [2] 80 fb [2] bd }

  condition:
    any of them
}