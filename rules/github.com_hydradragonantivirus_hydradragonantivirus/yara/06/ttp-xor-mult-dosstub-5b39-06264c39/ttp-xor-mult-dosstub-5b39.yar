rule TTP_XOR_MULT_DOSStub_5b39 {
  strings:
    $key_5b39 = { 0f 51 [2] 7b 49 [2] 3c 4b [2] 7b 5a [2] 35 56 [2] 39 5c [2] 2e 57 [2] 35 19 [2] 08 }

  condition:
    any of them
}