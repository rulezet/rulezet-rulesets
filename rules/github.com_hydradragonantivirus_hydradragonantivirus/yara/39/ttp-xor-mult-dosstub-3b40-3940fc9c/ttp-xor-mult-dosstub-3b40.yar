rule TTP_XOR_MULT_DOSStub_3b40 {
  strings:
    $key_3b40 = { 6f 28 [2] 1b 30 [2] 5c 32 [2] 1b 23 [2] 55 2f [2] 59 25 [2] 4e 2e [2] 55 60 [2] 68 }

  condition:
    any of them
}