rule TTP_XOR_MULT_DOSStub_dc94 {
  strings:
    $key_dc94 = { 88 fc [2] fc e4 [2] bb e6 [2] fc f7 [2] b2 fb [2] be f1 [2] a9 fa [2] b2 b4 [2] 8f }

  condition:
    any of them
}