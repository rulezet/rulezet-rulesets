rule TTP_XOR_MULT_DOSStub_3c20 {
  strings:
    $key_3c20 = { 68 48 [2] 1c 50 [2] 5b 52 [2] 1c 43 [2] 52 4f [2] 5e 45 [2] 49 4e [2] 52 00 [2] 6f }

  condition:
    any of them
}