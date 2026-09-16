rule TTP_XOR_MULT_DOSStub_5b10 {
  strings:
    $key_5b10 = { 0f 78 [2] 7b 60 [2] 3c 62 [2] 7b 73 [2] 35 7f [2] 39 75 [2] 2e 7e [2] 35 30 [2] 08 }

  condition:
    any of them
}