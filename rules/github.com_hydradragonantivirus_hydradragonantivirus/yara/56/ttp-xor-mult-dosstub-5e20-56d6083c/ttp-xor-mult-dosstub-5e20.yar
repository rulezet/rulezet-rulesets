rule TTP_XOR_MULT_DOSStub_5e20 {
  strings:
    $key_5e20 = { 0a 48 [2] 7e 50 [2] 39 52 [2] 7e 43 [2] 30 4f [2] 3c 45 [2] 2b 4e [2] 30 00 [2] 0d }

  condition:
    any of them
}