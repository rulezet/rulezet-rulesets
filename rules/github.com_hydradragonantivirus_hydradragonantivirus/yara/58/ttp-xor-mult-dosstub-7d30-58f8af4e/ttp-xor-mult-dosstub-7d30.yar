rule TTP_XOR_MULT_DOSStub_7d30 {
  strings:
    $key_7d30 = { 29 58 [2] 5d 40 [2] 1a 42 [2] 5d 53 [2] 13 5f [2] 1f 55 [2] 08 5e [2] 13 10 [2] 2e }

  condition:
    any of them
}