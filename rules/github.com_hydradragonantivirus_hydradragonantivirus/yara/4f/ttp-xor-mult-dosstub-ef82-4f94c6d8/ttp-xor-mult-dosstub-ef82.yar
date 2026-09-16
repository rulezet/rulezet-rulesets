rule TTP_XOR_MULT_DOSStub_ef82 {
  strings:
    $key_ef82 = { bb ea [2] cf f2 [2] 88 f0 [2] cf e1 [2] 81 ed [2] 8d e7 [2] 9a ec [2] 81 a2 [2] bc }

  condition:
    any of them
}