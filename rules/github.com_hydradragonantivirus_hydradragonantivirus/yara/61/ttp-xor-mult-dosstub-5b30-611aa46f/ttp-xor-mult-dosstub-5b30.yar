rule TTP_XOR_MULT_DOSStub_5b30 {
  strings:
    $key_5b30 = { 0f 58 [2] 7b 40 [2] 3c 42 [2] 7b 53 [2] 35 5f [2] 39 55 [2] 2e 5e [2] 35 10 [2] 08 }

  condition:
    any of them
}