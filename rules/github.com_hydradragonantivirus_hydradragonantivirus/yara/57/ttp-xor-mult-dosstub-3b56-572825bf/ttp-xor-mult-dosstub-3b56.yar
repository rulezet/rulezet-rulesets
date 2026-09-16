rule TTP_XOR_MULT_DOSStub_3b56 {
  strings:
    $key_3b56 = { 6f 3e [2] 1b 26 [2] 5c 24 [2] 1b 35 [2] 55 39 [2] 59 33 [2] 4e 38 [2] 55 76 [2] 68 }

  condition:
    any of them
}