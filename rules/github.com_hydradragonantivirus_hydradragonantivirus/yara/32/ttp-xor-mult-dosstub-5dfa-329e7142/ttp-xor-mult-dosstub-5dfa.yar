rule TTP_XOR_MULT_DOSStub_5dfa {
  strings:
    $key_5dfa = { 09 92 [2] 7d 8a [2] 3a 88 [2] 7d 99 [2] 33 95 [2] 3f 9f [2] 28 94 [2] 33 da [2] 0e }

  condition:
    any of them
}