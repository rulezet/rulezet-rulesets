rule TTP_XOR_MULT_DOSStub_5b07 {
  strings:
    $key_5b07 = { 0f 6f [2] 7b 77 [2] 3c 75 [2] 7b 64 [2] 35 68 [2] 39 62 [2] 2e 69 [2] 35 27 [2] 08 }

  condition:
    any of them
}