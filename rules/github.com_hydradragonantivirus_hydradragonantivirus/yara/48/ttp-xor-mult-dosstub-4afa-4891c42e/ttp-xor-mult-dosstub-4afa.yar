rule TTP_XOR_MULT_DOSStub_4afa {
  strings:
    $key_4afa = { 1e 92 [2] 6a 8a [2] 2d 88 [2] 6a 99 [2] 24 95 [2] 28 9f [2] 3f 94 [2] 24 da [2] 19 }

  condition:
    any of them
}