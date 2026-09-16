rule TTP_XOR_MULT_DOSStub_3b41 {
  strings:
    $key_3b41 = { 6f 29 [2] 1b 31 [2] 5c 33 [2] 1b 22 [2] 55 2e [2] 59 24 [2] 4e 2f [2] 55 61 [2] 68 }

  condition:
    any of them
}