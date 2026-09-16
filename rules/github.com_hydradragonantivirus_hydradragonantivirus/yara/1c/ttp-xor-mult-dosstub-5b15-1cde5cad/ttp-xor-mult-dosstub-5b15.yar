rule TTP_XOR_MULT_DOSStub_5b15 {
  strings:
    $key_5b15 = { 0f 7d [2] 7b 65 [2] 3c 67 [2] 7b 76 [2] 35 7a [2] 39 70 [2] 2e 7b [2] 35 35 [2] 08 }

  condition:
    any of them
}