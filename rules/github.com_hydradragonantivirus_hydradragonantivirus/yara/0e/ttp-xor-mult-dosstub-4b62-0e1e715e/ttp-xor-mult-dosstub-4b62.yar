rule TTP_XOR_MULT_DOSStub_4b62 {
  strings:
    $key_4b62 = { 1f 0a [2] 6b 12 [2] 2c 10 [2] 6b 01 [2] 25 0d [2] 29 07 [2] 3e 0c [2] 25 42 [2] 18 }

  condition:
    any of them
}