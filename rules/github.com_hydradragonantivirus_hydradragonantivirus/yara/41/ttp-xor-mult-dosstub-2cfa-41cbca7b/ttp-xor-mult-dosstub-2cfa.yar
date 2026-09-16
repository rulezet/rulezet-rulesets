rule TTP_XOR_MULT_DOSStub_2cfa {
  strings:
    $key_2cfa = { 78 92 [2] 0c 8a [2] 4b 88 [2] 0c 99 [2] 42 95 [2] 4e 9f [2] 59 94 [2] 42 da [2] 7f }

  condition:
    any of them
}