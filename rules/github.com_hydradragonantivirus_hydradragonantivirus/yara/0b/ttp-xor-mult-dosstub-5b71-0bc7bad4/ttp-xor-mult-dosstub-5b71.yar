rule TTP_XOR_MULT_DOSStub_5b71 {
  strings:
    $key_5b71 = { 0f 19 [2] 7b 01 [2] 3c 03 [2] 7b 12 [2] 35 1e [2] 39 14 [2] 2e 1f [2] 35 51 [2] 08 }

  condition:
    any of them
}