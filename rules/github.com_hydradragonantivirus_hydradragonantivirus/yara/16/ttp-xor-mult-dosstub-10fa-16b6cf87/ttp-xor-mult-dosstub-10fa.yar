rule TTP_XOR_MULT_DOSStub_10fa {
  strings:
    $key_10fa = { 44 92 [2] 30 8a [2] 77 88 [2] 30 99 [2] 7e 95 [2] 72 9f [2] 65 94 [2] 7e da [2] 43 }

  condition:
    any of them
}