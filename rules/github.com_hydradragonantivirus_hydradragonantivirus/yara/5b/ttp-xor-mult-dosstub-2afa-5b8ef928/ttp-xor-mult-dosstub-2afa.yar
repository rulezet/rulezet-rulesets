rule TTP_XOR_MULT_DOSStub_2afa {
  strings:
    $key_2afa = { 7e 92 [2] 0a 8a [2] 4d 88 [2] 0a 99 [2] 44 95 [2] 48 9f [2] 5f 94 [2] 44 da [2] 79 }

  condition:
    any of them
}