rule TTP_XOR_MULT_DOSStub_59e0 {
  strings:
    $key_59e0 = { 0d 88 [2] 79 90 [2] 3e 92 [2] 79 83 [2] 37 8f [2] 3b 85 [2] 2c 8e [2] 37 c0 [2] 0a }

  condition:
    any of them
}