rule TTP_XOR_MULT_DOSStub_59f7 {
  strings:
    $key_59f7 = { 0d 9f [2] 79 87 [2] 3e 85 [2] 79 94 [2] 37 98 [2] 3b 92 [2] 2c 99 [2] 37 d7 [2] 0a }

  condition:
    any of them
}