rule TTP_XOR_MULT_DOSStub_ef96 {
  strings:
    $key_ef96 = { bb fe [2] cf e6 [2] 88 e4 [2] cf f5 [2] 81 f9 [2] 8d f3 [2] 9a f8 [2] 81 b6 [2] bc }

  condition:
    any of them
}