rule TTP_XOR_MULT_DOSStub_5b21 {
  strings:
    $key_5b21 = { 0f 49 [2] 7b 51 [2] 3c 53 [2] 7b 42 [2] 35 4e [2] 39 44 [2] 2e 4f [2] 35 01 [2] 08 }

  condition:
    any of them
}