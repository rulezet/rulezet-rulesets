rule TTP_XOR_MULT_DOSStub_ef81 {
  strings:
    $key_ef81 = { bb e9 [2] cf f1 [2] 88 f3 [2] cf e2 [2] 81 ee [2] 8d e4 [2] 9a ef [2] 81 a1 [2] bc }

  condition:
    any of them
}