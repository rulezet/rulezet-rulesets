rule TTP_XOR_MULT_DOSStub_5b57 {
  strings:
    $key_5b57 = { 0f 3f [2] 7b 27 [2] 3c 25 [2] 7b 34 [2] 35 38 [2] 39 32 [2] 2e 39 [2] 35 77 [2] 08 }

  condition:
    any of them
}