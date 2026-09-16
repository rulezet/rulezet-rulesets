rule TTP_XOR_MULT_DOSStub_ef84 {
  strings:
    $key_ef84 = { bb ec [2] cf f4 [2] 88 f6 [2] cf e7 [2] 81 eb [2] 8d e1 [2] 9a ea [2] 81 a4 [2] bc }

  condition:
    any of them
}