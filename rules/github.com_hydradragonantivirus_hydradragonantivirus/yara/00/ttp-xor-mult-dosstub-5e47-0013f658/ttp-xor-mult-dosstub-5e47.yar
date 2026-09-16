rule TTP_XOR_MULT_DOSStub_5e47 {
  strings:
    $key_5e47 = { 0a 2f [2] 7e 37 [2] 39 35 [2] 7e 24 [2] 30 28 [2] 3c 22 [2] 2b 29 [2] 30 67 [2] 0d }

  condition:
    any of them
}