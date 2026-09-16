rule TTP_XOR_MULT_DOSStub_bbd1 {
  strings:
    $key_bbd1 = { ef b9 [2] 9b a1 [2] dc a3 [2] 9b b2 [2] d5 be [2] d9 b4 [2] ce bf [2] d5 f1 [2] e8 }

  condition:
    any of them
}