rule TTP_XOR_MULT_DOSStub_71fa {
  strings:
    $key_71fa = { 25 92 [2] 51 8a [2] 16 88 [2] 51 99 [2] 1f 95 [2] 13 9f [2] 04 94 [2] 1f da [2] 22 }

  condition:
    any of them
}