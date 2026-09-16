rule TTP_XOR_MULT_DOSStub_5b08 {
  strings:
    $key_5b08 = { 0f 60 [2] 7b 78 [2] 3c 7a [2] 7b 6b [2] 35 67 [2] 39 6d [2] 2e 66 [2] 35 28 [2] 08 }

  condition:
    any of them
}