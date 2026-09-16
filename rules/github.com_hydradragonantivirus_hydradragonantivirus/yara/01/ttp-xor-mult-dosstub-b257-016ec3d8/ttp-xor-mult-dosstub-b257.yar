rule TTP_XOR_MULT_DOSStub_b257 {
  strings:
    $key_b257 = { e6 3f [2] 92 27 [2] d5 25 [2] 92 34 [2] dc 38 [2] d0 32 [2] c7 39 [2] dc 77 [2] e1 }

  condition:
    any of them
}