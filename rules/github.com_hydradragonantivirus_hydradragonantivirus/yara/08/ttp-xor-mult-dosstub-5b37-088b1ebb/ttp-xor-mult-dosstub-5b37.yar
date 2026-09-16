rule TTP_XOR_MULT_DOSStub_5b37 {
  strings:
    $key_5b37 = { 0f 5f [2] 7b 47 [2] 3c 45 [2] 7b 54 [2] 35 58 [2] 39 52 [2] 2e 59 [2] 35 17 [2] 08 }

  condition:
    any of them
}