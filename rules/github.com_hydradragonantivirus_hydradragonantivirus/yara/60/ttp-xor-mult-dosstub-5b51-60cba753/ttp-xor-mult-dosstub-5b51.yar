rule TTP_XOR_MULT_DOSStub_5b51 {
  strings:
    $key_5b51 = { 0f 39 [2] 7b 21 [2] 3c 23 [2] 7b 32 [2] 35 3e [2] 39 34 [2] 2e 3f [2] 35 71 [2] 08 }

  condition:
    any of them
}