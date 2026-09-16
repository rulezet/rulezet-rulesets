rule TTP_XOR_MULT_DOSStub_5b79 {
  strings:
    $key_5b79 = { 0f 11 [2] 7b 09 [2] 3c 0b [2] 7b 1a [2] 35 16 [2] 39 1c [2] 2e 17 [2] 35 59 [2] 08 }

  condition:
    any of them
}