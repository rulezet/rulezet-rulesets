rule TTP_XOR_MULT_DOSStub_4c20 {
  strings:
    $key_4c20 = { 18 48 [2] 6c 50 [2] 2b 52 [2] 6c 43 [2] 22 4f [2] 2e 45 [2] 39 4e [2] 22 00 [2] 1f }

  condition:
    any of them
}