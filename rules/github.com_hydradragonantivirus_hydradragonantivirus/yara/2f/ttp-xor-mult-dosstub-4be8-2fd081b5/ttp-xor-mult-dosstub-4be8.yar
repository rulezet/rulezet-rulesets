rule TTP_XOR_MULT_DOSStub_4be8 {
  strings:
    $key_4be8 = { 1f 80 [2] 6b 98 [2] 2c 9a [2] 6b 8b [2] 25 87 [2] 29 8d [2] 3e 86 [2] 25 c8 [2] 18 }

  condition:
    any of them
}