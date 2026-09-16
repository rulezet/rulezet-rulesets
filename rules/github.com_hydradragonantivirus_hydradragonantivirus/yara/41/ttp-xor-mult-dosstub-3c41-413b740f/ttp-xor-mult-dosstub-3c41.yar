rule TTP_XOR_MULT_DOSStub_3c41 {
  strings:
    $key_3c41 = { 68 29 [2] 1c 31 [2] 5b 33 [2] 1c 22 [2] 52 2e [2] 5e 24 [2] 49 2f [2] 52 61 [2] 6f }

  condition:
    any of them
}