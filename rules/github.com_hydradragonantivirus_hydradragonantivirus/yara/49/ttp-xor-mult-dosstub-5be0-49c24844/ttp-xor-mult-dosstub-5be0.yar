rule TTP_XOR_MULT_DOSStub_5be0 {
  strings:
    $key_5be0 = { 0f 88 [2] 7b 90 [2] 3c 92 [2] 7b 83 [2] 35 8f [2] 39 85 [2] 2e 8e [2] 35 c0 [2] 08 }

  condition:
    any of them
}