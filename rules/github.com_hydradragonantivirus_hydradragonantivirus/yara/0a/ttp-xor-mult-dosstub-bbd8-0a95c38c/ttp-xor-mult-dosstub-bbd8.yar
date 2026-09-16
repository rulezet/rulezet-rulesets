rule TTP_XOR_MULT_DOSStub_bbd8 {
  strings:
    $key_bbd8 = { ef b0 [2] 9b a8 [2] dc aa [2] 9b bb [2] d5 b7 [2] d9 bd [2] ce b6 [2] d5 f8 [2] e8 }

  condition:
    any of them
}