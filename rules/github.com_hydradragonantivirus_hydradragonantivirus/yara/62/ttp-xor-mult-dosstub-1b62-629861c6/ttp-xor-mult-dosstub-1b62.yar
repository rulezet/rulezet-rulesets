rule TTP_XOR_MULT_DOSStub_1b62 {
  strings:
    $key_1b62 = { 4f 0a [2] 3b 12 [2] 7c 10 [2] 3b 01 [2] 75 0d [2] 79 07 [2] 6e 0c [2] 75 42 [2] 48 }

  condition:
    any of them
}