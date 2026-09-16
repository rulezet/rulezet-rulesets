rule TTP_XOR_MULT_DOSStub_dd93 {
  strings:
    $key_dd93 = { 89 fb [2] fd e3 [2] ba e1 [2] fd f0 [2] b3 fc [2] bf f6 [2] a8 fd [2] b3 b3 [2] 8e }

  condition:
    any of them
}