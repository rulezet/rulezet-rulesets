rule TTP_XOR_MULT_DOSStub_4be9 {
  strings:
    $key_4be9 = { 1f 81 [2] 6b 99 [2] 2c 9b [2] 6b 8a [2] 25 86 [2] 29 8c [2] 3e 87 [2] 25 c9 [2] 18 }

  condition:
    any of them
}