rule TTP_XOR_MULT_DOSStub_20fa {
  strings:
    $key_20fa = { 74 92 [2] 00 8a [2] 47 88 [2] 00 99 [2] 4e 95 [2] 42 9f [2] 55 94 [2] 4e da [2] 73 }

  condition:
    any of them
}