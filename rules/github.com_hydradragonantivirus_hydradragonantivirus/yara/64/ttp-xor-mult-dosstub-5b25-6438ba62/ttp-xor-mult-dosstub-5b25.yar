rule TTP_XOR_MULT_DOSStub_5b25 {
  strings:
    $key_5b25 = { 0f 4d [2] 7b 55 [2] 3c 57 [2] 7b 46 [2] 35 4a [2] 39 40 [2] 2e 4b [2] 35 05 [2] 08 }

  condition:
    any of them
}