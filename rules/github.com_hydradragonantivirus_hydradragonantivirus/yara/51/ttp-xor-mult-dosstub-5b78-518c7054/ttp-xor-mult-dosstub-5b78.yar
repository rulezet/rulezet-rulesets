rule TTP_XOR_MULT_DOSStub_5b78 {
  strings:
    $key_5b78 = { 0f 10 [2] 7b 08 [2] 3c 0a [2] 7b 1b [2] 35 17 [2] 39 1d [2] 2e 16 [2] 35 58 [2] 08 }

  condition:
    any of them
}