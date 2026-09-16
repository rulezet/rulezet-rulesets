rule TTP_XOR_MULT_DOSStub_3cfa {
  strings:
    $key_3cfa = { 68 92 [2] 1c 8a [2] 5b 88 [2] 1c 99 [2] 52 95 [2] 5e 9f [2] 49 94 [2] 52 da [2] 6f }

  condition:
    any of them
}