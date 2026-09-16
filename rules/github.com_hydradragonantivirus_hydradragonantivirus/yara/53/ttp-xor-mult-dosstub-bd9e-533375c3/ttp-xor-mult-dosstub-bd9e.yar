rule TTP_XOR_MULT_DOSStub_bd9e {
  strings:
    $key_bd9e = { e9 f6 [2] 9d ee [2] da ec [2] 9d fd [2] d3 f1 [2] df fb [2] c8 f0 [2] d3 be [2] ee }

  condition:
    any of them
}