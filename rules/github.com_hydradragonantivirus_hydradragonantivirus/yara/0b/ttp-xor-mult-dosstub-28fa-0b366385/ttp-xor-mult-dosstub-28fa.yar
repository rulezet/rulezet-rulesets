rule TTP_XOR_MULT_DOSStub_28fa {
  strings:
    $key_28fa = { 7c 92 [2] 08 8a [2] 4f 88 [2] 08 99 [2] 46 95 [2] 4a 9f [2] 5d 94 [2] 46 da [2] 7b }

  condition:
    any of them
}