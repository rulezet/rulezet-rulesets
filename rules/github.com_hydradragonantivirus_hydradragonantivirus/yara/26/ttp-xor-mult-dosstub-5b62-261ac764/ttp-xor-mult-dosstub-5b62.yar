rule TTP_XOR_MULT_DOSStub_5b62 {
  strings:
    $key_5b62 = { 0f 0a [2] 7b 12 [2] 3c 10 [2] 7b 01 [2] 35 0d [2] 39 07 [2] 2e 0c [2] 35 42 [2] 08 }

  condition:
    any of them
}