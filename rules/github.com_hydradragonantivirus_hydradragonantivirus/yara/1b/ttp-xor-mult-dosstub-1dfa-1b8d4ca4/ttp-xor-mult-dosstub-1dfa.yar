rule TTP_XOR_MULT_DOSStub_1dfa {
  strings:
    $key_1dfa = { 49 92 [2] 3d 8a [2] 7a 88 [2] 3d 99 [2] 73 95 [2] 7f 9f [2] 68 94 [2] 73 da [2] 4e }

  condition:
    any of them
}