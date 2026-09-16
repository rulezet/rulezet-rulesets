rule TTP_XOR_MULT_DOSStub_5b61 {
  strings:
    $key_5b61 = { 0f 09 [2] 7b 11 [2] 3c 13 [2] 7b 02 [2] 35 0e [2] 39 04 [2] 2e 0f [2] 35 41 [2] 08 }

  condition:
    any of them
}