rule TTP_XOR_MULT_DOSStub_bbd0 {
  strings:
    $key_bbd0 = { ef b8 [2] 9b a0 [2] dc a2 [2] 9b b3 [2] d5 bf [2] d9 b5 [2] ce be [2] d5 f0 [2] e8 }

  condition:
    any of them
}