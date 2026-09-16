rule TTP_XOR_MULT_DOSStub_7b40 {
  strings:
    $key_7b40 = { 2f 28 [2] 5b 30 [2] 1c 32 [2] 5b 23 [2] 15 2f [2] 19 25 [2] 0e 2e [2] 15 60 [2] 28 }

  condition:
    any of them
}