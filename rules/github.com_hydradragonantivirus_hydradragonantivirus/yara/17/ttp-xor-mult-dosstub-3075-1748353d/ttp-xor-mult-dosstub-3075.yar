rule TTP_XOR_MULT_DOSStub_3075 {
  strings:
    $key_3075 = { 64 1d [2] 10 05 [2] 57 07 [2] 10 16 [2] 5e 1a [2] 52 10 [2] 45 1b [2] 5e 55 [2] 63 }

  condition:
    any of them
}