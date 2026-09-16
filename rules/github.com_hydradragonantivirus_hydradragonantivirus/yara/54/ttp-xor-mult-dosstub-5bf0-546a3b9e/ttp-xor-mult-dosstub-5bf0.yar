rule TTP_XOR_MULT_DOSStub_5bf0 {
  strings:
    $key_5bf0 = { 0f 98 [2] 7b 80 [2] 3c 82 [2] 7b 93 [2] 35 9f [2] 39 95 [2] 2e 9e [2] 35 d0 [2] 08 }

  condition:
    any of them
}