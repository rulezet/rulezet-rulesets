rule TTP_XOR_MULT_DOSStub_59e4 {
  strings:
    $key_59e4 = { 0d 8c [2] 79 94 [2] 3e 96 [2] 79 87 [2] 37 8b [2] 3b 81 [2] 2c 8a [2] 37 c4 [2] 0a }

  condition:
    any of them
}