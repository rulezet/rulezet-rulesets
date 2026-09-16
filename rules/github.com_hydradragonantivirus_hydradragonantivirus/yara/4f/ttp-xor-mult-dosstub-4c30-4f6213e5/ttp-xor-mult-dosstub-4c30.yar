rule TTP_XOR_MULT_DOSStub_4c30 {
  strings:
    $key_4c30 = { 18 58 [2] 6c 40 [2] 2b 42 [2] 6c 53 [2] 22 5f [2] 2e 55 [2] 39 5e [2] 22 10 [2] 1f }

  condition:
    any of them
}