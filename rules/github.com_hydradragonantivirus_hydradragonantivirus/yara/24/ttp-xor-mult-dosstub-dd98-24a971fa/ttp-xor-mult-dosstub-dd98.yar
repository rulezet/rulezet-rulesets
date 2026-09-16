rule TTP_XOR_MULT_DOSStub_dd98 {
  strings:
    $key_dd98 = { 89 f0 [2] fd e8 [2] ba ea [2] fd fb [2] b3 f7 [2] bf fd [2] a8 f6 [2] b3 b8 [2] 8e }

  condition:
    any of them
}