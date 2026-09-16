rule TTP_XOR_MULT_DOSStub_4b5b {
  strings:
    $key_4b5b = { 1f 33 [2] 6b 2b [2] 2c 29 [2] 6b 38 [2] 25 34 [2] 29 3e [2] 3e 35 [2] 25 7b [2] 18 }

  condition:
    any of them
}