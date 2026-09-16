rule TTP_XOR_MULT_DOSStub_5e40 {
  strings:
    $key_5e40 = { 0a 28 [2] 7e 30 [2] 39 32 [2] 7e 23 [2] 30 2f [2] 3c 25 [2] 2b 2e [2] 30 60 [2] 0d }

  condition:
    any of them
}