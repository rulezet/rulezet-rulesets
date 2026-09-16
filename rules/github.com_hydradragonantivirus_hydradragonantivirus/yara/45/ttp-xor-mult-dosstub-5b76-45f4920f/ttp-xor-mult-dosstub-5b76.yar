rule TTP_XOR_MULT_DOSStub_5b76 {
  strings:
    $key_5b76 = { 0f 1e [2] 7b 06 [2] 3c 04 [2] 7b 15 [2] 35 19 [2] 39 13 [2] 2e 18 [2] 35 56 [2] 08 }

  condition:
    any of them
}