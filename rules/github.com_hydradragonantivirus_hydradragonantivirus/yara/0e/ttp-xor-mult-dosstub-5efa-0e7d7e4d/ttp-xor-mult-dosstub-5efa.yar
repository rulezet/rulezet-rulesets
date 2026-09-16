rule TTP_XOR_MULT_DOSStub_5efa {
  strings:
    $key_5efa = { 0a 92 [2] 7e 8a [2] 39 88 [2] 7e 99 [2] 30 95 [2] 3c 9f [2] 2b 94 [2] 30 da [2] 0d }

  condition:
    any of them
}