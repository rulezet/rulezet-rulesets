rule TTP_XOR_MULT_DOSStub_7ffa {
  strings:
    $key_7ffa = { 2b 92 [2] 5f 8a [2] 18 88 [2] 5f 99 [2] 11 95 [2] 1d 9f [2] 0a 94 [2] 11 da [2] 2c }

  condition:
    any of them
}