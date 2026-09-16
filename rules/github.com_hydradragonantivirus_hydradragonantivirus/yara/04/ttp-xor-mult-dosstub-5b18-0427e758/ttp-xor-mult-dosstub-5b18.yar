rule TTP_XOR_MULT_DOSStub_5b18 {
  strings:
    $key_5b18 = { 0f 70 [2] 7b 68 [2] 3c 6a [2] 7b 7b [2] 35 77 [2] 39 7d [2] 2e 76 [2] 35 38 [2] 08 }

  condition:
    any of them
}