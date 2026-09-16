rule TTP_XOR_MULT_DOSStub_8893 {
  strings:
    $key_8893 = { dc fb [2] a8 e3 [2] ef e1 [2] a8 f0 [2] e6 fc [2] ea f6 [2] fd fd [2] e6 b3 [2] db }

  condition:
    any of them
}