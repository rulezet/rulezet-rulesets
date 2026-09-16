rule TTP_XOR_MULT_DOSStub_1bfa {
  strings:
    $key_1bfa = { 4f 92 [2] 3b 8a [2] 7c 88 [2] 3b 99 [2] 75 95 [2] 79 9f [2] 6e 94 [2] 75 da [2] 48 }

  condition:
    any of them
}