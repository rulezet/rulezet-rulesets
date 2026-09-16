rule TTP_XOR_MULT_DOSStub_5afa {
  strings:
    $key_5afa = { 0e 92 [2] 7a 8a [2] 3d 88 [2] 7a 99 [2] 34 95 [2] 38 9f [2] 2f 94 [2] 34 da [2] 09 }

  condition:
    any of them
}