rule TTP_XOR_MULT_DOSStub_0e20 {
  strings:
    $key_0e20 = { 5a 48 [2] 2e 50 [2] 69 52 [2] 2e 43 [2] 60 4f [2] 6c 45 [2] 7b 4e [2] 60 00 [2] 5d }

  condition:
    any of them
}