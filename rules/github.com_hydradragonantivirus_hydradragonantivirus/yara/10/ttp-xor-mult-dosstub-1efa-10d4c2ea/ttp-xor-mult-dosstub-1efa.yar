rule TTP_XOR_MULT_DOSStub_1efa {
  strings:
    $key_1efa = { 4a 92 [2] 3e 8a [2] 79 88 [2] 3e 99 [2] 70 95 [2] 7c 9f [2] 6b 94 [2] 70 da [2] 4d }

  condition:
    any of them
}