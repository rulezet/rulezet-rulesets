rule TTP_XOR_MULT_DOSStub_5b41 {
  strings:
    $key_5b41 = { 0f 29 [2] 7b 31 [2] 3c 33 [2] 7b 22 [2] 35 2e [2] 39 24 [2] 2e 2f [2] 35 61 [2] 08 }

  condition:
    any of them
}