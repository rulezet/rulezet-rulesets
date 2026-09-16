rule TTP_XOR_MULT_DOSStub_f898 {
  strings:
    $key_f898 = { ac f0 [2] d8 e8 [2] 9f ea [2] d8 fb [2] 96 f7 [2] 9a fd [2] 8d f6 [2] 96 b8 [2] ab }

  condition:
    any of them
}