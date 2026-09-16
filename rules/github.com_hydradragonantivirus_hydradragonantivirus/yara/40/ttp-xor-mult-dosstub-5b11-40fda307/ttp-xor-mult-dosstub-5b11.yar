rule TTP_XOR_MULT_DOSStub_5b11 {
  strings:
    $key_5b11 = { 0f 79 [2] 7b 61 [2] 3c 63 [2] 7b 72 [2] 35 7e [2] 39 74 [2] 2e 7f [2] 35 31 [2] 08 }

  condition:
    any of them
}