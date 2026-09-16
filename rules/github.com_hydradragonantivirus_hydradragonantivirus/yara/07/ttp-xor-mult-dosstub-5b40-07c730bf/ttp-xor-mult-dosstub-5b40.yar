rule TTP_XOR_MULT_DOSStub_5b40 {
  strings:
    $key_5b40 = { 0f 28 [2] 7b 30 [2] 3c 32 [2] 7b 23 [2] 35 2f [2] 39 25 [2] 2e 2e [2] 35 60 [2] 08 }

  condition:
    any of them
}