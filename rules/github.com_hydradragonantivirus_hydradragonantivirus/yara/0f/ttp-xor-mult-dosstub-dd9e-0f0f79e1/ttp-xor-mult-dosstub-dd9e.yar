rule TTP_XOR_MULT_DOSStub_dd9e {
  strings:
    $key_dd9e = { 89 f6 [2] fd ee [2] ba ec [2] fd fd [2] b3 f1 [2] bf fb [2] a8 f0 [2] b3 be [2] 8e }

  condition:
    any of them
}