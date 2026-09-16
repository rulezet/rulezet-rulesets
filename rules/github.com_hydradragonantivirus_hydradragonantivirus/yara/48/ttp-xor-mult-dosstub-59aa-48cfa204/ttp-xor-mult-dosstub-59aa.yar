rule TTP_XOR_MULT_DOSStub_59aa {
  strings:
    $key_59aa = { 0d c2 [2] 79 da [2] 3e d8 [2] 79 c9 [2] 37 c5 [2] 3b cf [2] 2c c4 [2] 37 8a [2] 0a }

  condition:
    any of them
}