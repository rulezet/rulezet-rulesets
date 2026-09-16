rule TTP_XOR_MULT_DOSStub_5b48 {
  strings:
    $key_5b48 = { 0f 20 [2] 7b 38 [2] 3c 3a [2] 7b 2b [2] 35 27 [2] 39 2d [2] 2e 26 [2] 35 68 [2] 08 }

  condition:
    any of them
}