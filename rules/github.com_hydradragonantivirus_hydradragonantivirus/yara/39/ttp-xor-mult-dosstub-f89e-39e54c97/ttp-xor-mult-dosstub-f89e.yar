rule TTP_XOR_MULT_DOSStub_f89e {
  strings:
    $key_f89e = { ac f6 [2] d8 ee [2] 9f ec [2] d8 fd [2] 96 f1 [2] 9a fb [2] 8d f0 [2] 96 be [2] ab }

  condition:
    any of them
}