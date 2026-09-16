rule TTP_XOR_MULT_DOSStub_2ffa {
  strings:
    $key_2ffa = { 7b 92 [2] 0f 8a [2] 48 88 [2] 0f 99 [2] 41 95 [2] 4d 9f [2] 5a 94 [2] 41 da [2] 7c }

  condition:
    any of them
}