rule TTP_XOR_MULT_DOSStub_7bfa {
  strings:
    $key_7bfa = { 2f 92 [2] 5b 8a [2] 1c 88 [2] 5b 99 [2] 15 95 [2] 19 9f [2] 0e 94 [2] 15 da [2] 28 }

  condition:
    any of them
}